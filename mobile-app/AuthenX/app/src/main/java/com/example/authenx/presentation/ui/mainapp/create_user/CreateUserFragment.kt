package com.example.authenx.presentation.ui.mainapp.create_user

import android.os.Bundle
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.os.bundleOf
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.example.authenx.R
import com.example.authenx.databinding.FragmentCreateUserBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class CreateUserFragment : Fragment() {

    private var _binding: FragmentCreateUserBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: CreateUserViewModel by viewModels()
    
    private var hasNavigated = false

    companion object {
        private const val TAG = "CreateUserFragment"
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCreateUserBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupClickListeners()
        observeUiState()
    }
    
    private fun setupClickListeners() {
        binding.btnBack.setOnClickListener {
            findNavController().popBackStack()
        }
        
        binding.btnCreateUser.setOnClickListener {
            val fullName = binding.etFullName.text.toString().trim()
            val phone = binding.etPhone.text.toString().trim()
            viewModel.createUser(fullName, phone)
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
    
    private fun updateUi(state: CreateUserUiState) {
        Log.d(TAG, "updateUi - isLoading: ${state.isLoading}, success: ${state.success}, createdUserId: ${state.createdUserId}, hasNavigated: $hasNavigated")
        
        // Loading state
        binding.btnCreateUser.isEnabled = !state.isLoading
        binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE
        
        // Success state - only navigate once
        if (state.success && state.createdUserId != null && !hasNavigated) {
            hasNavigated = true
            
            Log.d(TAG, "✅ User created successfully: ${state.createdUserName}")
            
            Toast.makeText(
                requireContext(),
                "✅ User ${state.createdUserName} created successfully!",
                Toast.LENGTH_LONG
            ).show()
            
            // Reset state first
            viewModel.resetState()
            
            // Go back to user management, realtime will update the list
            Log.d(TAG, "Navigating back to UserManagement")
            findNavController().popBackStack()
        }
        
        // Error state
        state.error?.let { error ->
            Log.e(TAG, "Error creating user: $error")
            Toast.makeText(requireContext(), error, Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
