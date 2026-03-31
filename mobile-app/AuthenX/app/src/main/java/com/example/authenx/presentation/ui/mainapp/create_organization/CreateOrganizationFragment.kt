package com.example.authenx.presentation.ui.mainapp.create_organization

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
import com.example.authenx.databinding.FragmentCreateOrganizationBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class CreateOrganizationFragment : Fragment() {

    private var _binding: FragmentCreateOrganizationBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: CreateOrganizationViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentCreateOrganizationBinding.inflate(inflater, container, false)
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
        
        binding.btnCreateOrganization.setOnClickListener {
            val name = binding.etOrganizationName.text.toString().trim()
            val address = binding.etAddress.text.toString().trim()
            viewModel.createOrganization(name, address.ifEmpty { null })
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
    
    private fun updateUi(state: CreateOrganizationUiState) {
        // Loading state
        binding.btnCreateOrganization.isEnabled = !state.isLoading
        binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE
        
        // Success state
        if (state.success) {
            Toast.makeText(
                requireContext(),
                getString(R.string.create_organization_success, state.organizationName),
                Toast.LENGTH_SHORT
            ).show()
            
            viewModel.resetState()
            findNavController().popBackStack()
        }
        
        // Error state
        state.error?.let { error ->
            Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
