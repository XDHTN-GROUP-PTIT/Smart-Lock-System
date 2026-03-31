package com.example.authenx.presentation.ui.mainapp.edit_profile

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.authenx.R
import com.example.authenx.databinding.FragmentEditProfileBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class EditProfileFragment : Fragment() {

    private var _binding: FragmentEditProfileBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: EditProfileViewModel by viewModels()
    
    // userId from arguments (for editing other user_manager) or null (for editing own profile)
    private var userId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            userId = it.getString("userId")
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentEditProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupUI()
        loadUserData()
        observeUiState()
    }
    
    private fun setupUI() {
        binding.btnBack.setOnClickListener {
            findNavController().popBackStack()
        }
        
        binding.btnSave.setOnClickListener {
            saveChanges()
        }
    }
    
    private fun loadUserData() {
        viewModel.loadUserData(userId)
    }
    
    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                updateUI(state)
            }
        }
    }
    
    private fun updateUI(state: EditProfileUiState) {
        binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE
        binding.btnSave.isEnabled = !state.isLoading
        
        state.user?.let { user ->
            binding.etFullName.setText(user.fullName)
            binding.etEmail.setText(user.email)
            binding.etPhone.setText(user.phone)
        }
        
        state.error?.let { error ->
            Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
            viewModel.clearError()
        }
        
        if (state.success) {
            Toast.makeText(requireContext(), "Profile updated successfully", Toast.LENGTH_SHORT).show()
            findNavController().popBackStack()
        }
    }
    
    private fun saveChanges() {
        val fullName = binding.etFullName.text.toString().trim()
        val email = binding.etEmail.text.toString().trim()
        val phone = binding.etPhone.text.toString().trim()
        val oldPassword = binding.etOldPassword.text.toString()
        val newPassword = binding.etNewPassword.text.toString()
        val confirmPassword = binding.etConfirmPassword.text.toString()
        
        // Validation
        if (fullName.isEmpty()) {
            binding.tilFullName.error = "Full name is required"
            return
        }
        
        if (email.isEmpty()) {
            binding.tilEmail.error = "Email is required"
            return
        }
        
        if (!android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            binding.tilEmail.error = "Invalid email format"
            return
        }
        
        // Password validation (if changing password)
        if (oldPassword.isNotEmpty() || newPassword.isNotEmpty() || confirmPassword.isNotEmpty()) {
            if (oldPassword.isEmpty()) {
                binding.tilOldPassword.error = "Old password is required"
                return
            }
            
            if (newPassword.isEmpty()) {
                binding.tilNewPassword.error = "New password is required"
                return
            }
            
            if (newPassword.length < 6) {
                binding.tilNewPassword.error = "Password must be at least 6 characters"
                return
            }
            
            if (newPassword != confirmPassword) {
                binding.tilConfirmPassword.error = "Passwords do not match"
                return
            }
        }
        
        // Clear errors
        binding.tilFullName.error = null
        binding.tilEmail.error = null
        binding.tilPhone.error = null
        binding.tilOldPassword.error = null
        binding.tilNewPassword.error = null
        binding.tilConfirmPassword.error = null
        
        // Save
        viewModel.updateProfile(
            userId = userId,
            fullName = fullName,
            email = email,
            phone = phone.ifEmpty { null },
            oldPassword = oldPassword.ifEmpty { null },
            newPassword = newPassword.ifEmpty { null },
            confirmPassword = confirmPassword.ifEmpty { null }
        )
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
