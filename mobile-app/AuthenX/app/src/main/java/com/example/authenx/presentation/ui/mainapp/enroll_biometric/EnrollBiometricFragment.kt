package com.example.authenx.presentation.ui.mainapp.enroll_biometric

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.example.authenx.R
import com.example.authenx.databinding.FragmentEnrollBiometricBinding
import com.example.authenx.data.remote.socket.SocketManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class EnrollBiometricFragment : Fragment() {

    private var _binding: FragmentEnrollBiometricBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: EnrollBiometricViewModel by viewModels()
    
    @Inject
    lateinit var socketManager: SocketManager
    
    private var userId: String? = null
    private var userName: String? = null
    private var deviceId: String? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentEnrollBiometricBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        userId = arguments?.getString("userId")
        userName = arguments?.getString("userName")
        deviceId = arguments?.getString("deviceId")
        
        binding.tvUserName.text = getString(R.string.user_label, userName)
        
        setupClickListeners()
        observeUiState()
        observeSocketEvents()
    }
    
    private fun setupClickListeners() {
        binding.btnBack.setOnClickListener {
            findNavController().popBackStack()
        }
        
        binding.btnEnrollFingerprint.setOnClickListener {
            val uId = userId
            val dId = deviceId
            
            if (uId != null && dId != null) {
                viewModel.enrollFingerprint(uId, dId)
            } else {
                val missingParam = when {
                    uId == null -> "User ID"
                    dId == null -> "Device ID"
                    else -> "Required parameters"
                }
                Toast.makeText(requireContext(), "$missingParam not found", Toast.LENGTH_SHORT).show()
            }
        }
        
        binding.btnDone.setOnClickListener {
            findNavController().popBackStack(R.id.userManagementFragment, false)
        }
    }
    
    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    updateUi(state)
                }
            }
        }
    }
    
    private fun observeSocketEvents() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                socketManager.onFingerprintEnrolled().collect { event ->
                    // event contain { userId, fingerprintId, success, message }
                    if (event.userId == userId) {
                        if (event.success) {
                            viewModel.onEnrollmentComplete()
                        } else {
                            viewModel.onEnrollmentFailed(event.message ?: getString(R.string.enrollment_failed))
                        }
                    }
                }
            }
        }
    }
    
    private fun updateUi(state: EnrollBiometricUiState) {
        binding.progressBar.visibility = if (state.isEnrolling) View.VISIBLE else View.GONE
        
        // Update status text
        binding.tvStatus.text = state.enrollmentStatus
        
        // Update fingerprint ID
        state.fingerprintId?.let {
            binding.tvFingerprintId.text = getString(R.string.fingerprint_id_label, it)
            binding.tvFingerprintId.visibility = View.VISIBLE
        }
        
        // Show/hide buttons based on state
        binding.btnEnrollFingerprint.isEnabled = !state.isEnrolling && !state.success
        binding.btnDone.visibility = if (state.success) View.VISIBLE else View.GONE
        
        // Show instruction when waiting for ESP32
        if (state.waitingForEsp) {
            binding.tvInstruction.visibility = View.VISIBLE
            binding.imgFingerprint.visibility = View.VISIBLE
        } else {
            binding.tvInstruction.visibility = View.GONE
            binding.imgFingerprint.visibility = View.GONE
        }
        
        // Show error
        state.error?.let { error ->
            Toast.makeText(requireContext(), error, Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
