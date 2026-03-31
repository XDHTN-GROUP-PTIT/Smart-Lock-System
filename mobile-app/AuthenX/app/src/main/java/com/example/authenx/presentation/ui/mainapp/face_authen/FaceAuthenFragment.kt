package com.example.authenx.presentation.ui.mainapp.face_authen

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
import com.example.authenx.data.local.AuthManager
import com.example.authenx.databinding.FragmentFaceAuthenBinding
import com.example.authenx.domain.model.FaceRecognitionState
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import javax.inject.Inject

@AndroidEntryPoint
class FaceAuthenFragment : Fragment() {

    private var _binding: FragmentFaceAuthenBinding? = null
    private val binding get() = _binding!!
    private val viewModel: FaceAuthenViewModel by viewModels()
    private val args: FaceAuthenFragmentArgs by navArgs()
    
    @Inject
    lateinit var authManager: AuthManager
    
    private var imageCapture: ImageCapture? = null

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) startCamera()
        else {
            Toast.makeText(requireContext(), "Cần cấp quyền camera", Toast.LENGTH_SHORT).show()
            findNavController().popBackStack()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentFaceAuthenBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupClickListeners()
        observeUiState()
        checkCameraPermissionAndStart()
    }

    private fun setupClickListeners() {
        binding.btnCancel.setOnClickListener {
            findNavController().popBackStack()
        }
        
        binding.btnCapture.setOnClickListener {
            val state = viewModel.uiState.value.state
            when (state) {
                FaceRecognitionState.IDLE -> {
                    viewModel.capturePressed()
                    captureImage { base64 ->
                        Log.d("BASE_64 IMAGE", base64)
                        saveBase64ToFile(base64, "face_front.jpg")
                        viewModel.processFrontFace(base64)
                    }
                }
                FaceRecognitionState.WAITING_ACTION -> {
                    viewModel.capturePressed()
                    captureImage { base64 ->
                        saveBase64ToFile(base64, "face_action.jpg")
                        viewModel.processActionFace(base64)
                    }
                }
                FaceRecognitionState.ERROR -> {
                    viewModel.reset()
                }
                else -> {}
            }
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
    
    private fun updateUI(state: FaceAuthenUiState) {
        binding.tvInstruction.text = state.instruction
        binding.progressProcessing.isVisible = state.isLoading
        binding.btnCapture.isEnabled = !state.isLoading
        
        // Handle success - call unlock API only if deviceId is provided
        if (state.isUnlockSuccess && state.unlockMessage == null) {
            val deviceId = args.deviceId
            
            // If deviceId is provided, call unlock API (unlock flow)
            if (!deviceId.isNullOrEmpty()) {
                val token = authManager.getToken()
                if (token.isNullOrEmpty()) {
                    Toast.makeText(requireContext(), "Authentication token not found", Toast.LENGTH_SHORT).show()
                    findNavController().popBackStack()
                    return
                }
                
                viewModel.unlockDevice(deviceId, token)
            } else {
                // No deviceId - just face verification (from Home)
                Toast.makeText(requireContext(), "Face verified successfully!", Toast.LENGTH_SHORT).show()
                findNavController().popBackStack()
            }
        }
        
        // Hiển thị kết quả unlock
        state.unlockMessage?.let { message ->
            Toast.makeText(requireContext(), message, Toast.LENGTH_SHORT).show()
            findNavController().popBackStack()
        }
        
        // Handle error
        state.error?.let { error ->
            Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
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
                Log.e("FaceAuthen", "Camera start failed: ", exc)
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
                    Log.e("FaceAuthen", "Image capture failed", exception)
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
    
    private fun saveBase64ToFile(base64String: String, fileName: String) {
        try {
            // Decode base64 to bytes
            val imageBytes = Base64.decode(base64String, Base64.NO_WRAP)
            
            // Save to app's Pictures directory
            val picturesDir = requireContext().getExternalFilesDir(android.os.Environment.DIRECTORY_PICTURES)
            val imageFile = java.io.File(picturesDir, fileName)
            
            java.io.FileOutputStream(imageFile).use { fos ->
                fos.write(imageBytes)
            }
            
            Log.d("FaceAuthen", "✅ Image saved to: ${imageFile.absolutePath}")
            Toast.makeText(requireContext(), "Saved: ${imageFile.name}", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.e("FaceAuthen", "❌ Failed to save image", e)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}