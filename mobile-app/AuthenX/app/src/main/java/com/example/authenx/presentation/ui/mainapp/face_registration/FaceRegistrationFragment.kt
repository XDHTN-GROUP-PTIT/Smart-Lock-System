package com.example.authenx.presentation.ui.mainapp.face_registration

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.example.authenx.R
import com.example.authenx.data.local.AuthManager
import com.example.authenx.databinding.FragmentFaceRegistrationBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import javax.inject.Inject

@AndroidEntryPoint
class FaceRegistrationFragment : Fragment() {

    private var _binding: FragmentFaceRegistrationBinding? = null
    private val binding get() = _binding!!
    private val viewModel: FaceRegistrationViewModel by viewModels()
    
    @Inject
    lateinit var authManager: AuthManager
    
    private var imageCapture: ImageCapture? = null

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) startCamera()
        else {
            Toast.makeText(requireContext(), getString(R.string.camera_permission_required), Toast.LENGTH_SHORT).show()
            findNavController().popBackStack()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentFaceRegistrationBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        // Debug: Check stored user info
        val userId = authManager.getUserId()
        val userName = authManager.getUserName()
        val userRole = authManager.getUserRole()
        Log.d("FaceRegistration", "UserId: $userId, UserName: $userName, UserRole: $userRole")

        if (userRole != "user_manager") {
            Toast.makeText(requireContext(), "Chỉ user_manager mới được đăng ký khuôn mặt", Toast.LENGTH_LONG).show()
            findNavController().popBackStack()
            return
        }

        if (userId == null) {
            Toast.makeText(requireContext(), "Không tìm thấy thông tin người dùng. Vui lòng đăng nhập lại.", Toast.LENGTH_LONG).show()
            findNavController().popBackStack()
            return
        }
        
        setupUI()
        setupClickListeners()
        observeUiState()
        checkCameraPermissionAndStart()
    }

    private fun setupUI() {
        val userName = authManager.getUserName() ?: "User"
        binding.tvUserInfo.text = getString(R.string.register_face_for, userName)
        binding.tvInstruction.text = getString(R.string.place_face_instruction)
    }

    private fun setupClickListeners() {
        binding.btnCancel.setOnClickListener {
            findNavController().popBackStack()
        }
        
        binding.btnCapture.setOnClickListener {
            val state = viewModel.uiState.value.state
            when (state) {
                FaceRegistrationState.IDLE -> {
                    val userId = authManager.getUserId()
                    if (userId.isNullOrEmpty()) {
                        Toast.makeText(requireContext(), getString(R.string.user_info_not_found), Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    viewModel.capturePressed()
                    captureImage { base64 ->
                        viewModel.registerFace(base64, userId)
                    }
                }
                FaceRegistrationState.ERROR -> {
                    viewModel.reset()
                }
                FaceRegistrationState.SUCCESS -> {
                    findNavController().popBackStack()
                }
                else -> {}
            }
        }
        
        binding.btnDeleteFace.setOnClickListener {
            val userId = authManager.getUserId()
            if (userId.isNullOrEmpty()) {
                Toast.makeText(requireContext(), getString(R.string.user_info_not_found), Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            androidx.appcompat.app.AlertDialog.Builder(requireContext())
                .setTitle(getString(R.string.confirm_delete))
                .setMessage(getString(R.string.confirm_delete_face_message))
                .setPositiveButton(getString(R.string.delete)) { _, _ ->
                    viewModel.deleteFace(userId) {
                        Toast.makeText(requireContext(), getString(R.string.face_deleted_successfully), Toast.LENGTH_SHORT).show()
                        findNavController().popBackStack()
                    }
                }
                .setNegativeButton(getString(R.string.cancel), null)
                .show()
        }
    }
    
    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    updateUI(state)
                }
            }
        }
    }
    
    private fun updateUI(state: FaceRegistrationUiState) {
        binding.progressProcessing.isVisible = state.isLoading
        binding.btnCapture.isEnabled = !state.isLoading
        
        when (state.state) {
            FaceRegistrationState.IDLE -> {
                binding.tvInstruction.text = getString(R.string.place_face_instruction)
                binding.btnCapture.text = getString(R.string.capture_photo)
                binding.btnCapture.isEnabled = true
                binding.btnDeleteFace.isVisible = true
            }
            FaceRegistrationState.CAPTURING -> {
                binding.tvInstruction.text = getString(R.string.capturing_photo)
                binding.btnCapture.isEnabled = false
            }
            FaceRegistrationState.REGISTERING -> {
                binding.tvInstruction.text = state.message
                binding.btnCapture.isEnabled = false
                binding.btnDeleteFace.isVisible = false
            }
            FaceRegistrationState.SUCCESS -> {
                binding.tvInstruction.text = "✅ ${state.message}"
                binding.btnCapture.text = getString(R.string.done)
                binding.btnCapture.isEnabled = true
                binding.btnDeleteFace.isVisible = false
                
                // Show captured image preview
                state.capturedImage?.let { base64 ->
                    try {
                        val imageBytes = Base64.decode(base64, Base64.NO_WRAP)
                        val bitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)
                        binding.ivPreview.setImageBitmap(bitmap)
                        binding.ivPreview.isVisible = true
                    } catch (e: Exception) {
                        Log.e("FaceRegistration", "Failed to display preview", e)
                    }
                }
                
                Toast.makeText(requireContext(), getString(R.string.face_registered_successfully), Toast.LENGTH_SHORT).show()
            }
            FaceRegistrationState.ERROR -> {
                binding.tvInstruction.text = "❌ ${state.message}"
                binding.btnCapture.text = getString(R.string.try_again)
                binding.btnCapture.isEnabled = true
                binding.btnDeleteFace.isVisible = true
                binding.ivPreview.isVisible = false
                
                Toast.makeText(requireContext(), state.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun checkCameraPermissionAndStart() {
        val context = requireContext()
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(requireContext())

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(binding.previewView.surfaceProvider)
            }
            
            imageCapture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                .build()

            val cameraSelector = CameraSelector.DEFAULT_FRONT_CAMERA

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    viewLifecycleOwner,
                    cameraSelector,
                    preview,
                    imageCapture
                )
            } catch (exc: Exception) {
                Log.e("FaceRegistration", "Camera start failed: ", exc)
            }

        }, ContextCompat.getMainExecutor(requireContext()))
    }
    
    private fun captureImage(onImageCaptured: (String) -> Unit) {
        val imageCapture = imageCapture ?: return
        
        imageCapture.takePicture(
            ContextCompat.getMainExecutor(requireContext()),
            object : ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {
                    val base64 = imageProxyToBase64(image)
                    image.close()
                    onImageCaptured(base64)
                }

                override fun onError(exception: ImageCaptureException) {
                    Log.e("FaceRegistration", "Image capture failed", exception)
                    Toast.makeText(requireContext(), "Lỗi chụp ảnh", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }
    
    private fun imageProxyToBase64(image: ImageProxy): String {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)

        val base64String = Base64.encodeToString(bytes, Base64.NO_WRAP)

        Log.d("FaceAuthen", "Image format: ${image.format}, Base64 length: ${base64String.length}")

        return base64String
    }
    
    private fun imageProxyToBitmap(image: ImageProxy): Bitmap {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        
        var bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        
        // Rotate bitmap if needed based on image rotation
        val rotationDegrees = image.imageInfo.rotationDegrees
        if (rotationDegrees != 0) {
            val matrix = Matrix()
            matrix.postRotate(rotationDegrees.toFloat())
            bitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        }
        
        return bitmap
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
