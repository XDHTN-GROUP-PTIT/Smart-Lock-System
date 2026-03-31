package com.example.authenx.presentation.ui.mainapp.device

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.authenx.databinding.FragmentRegisterDeviceBinding
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class RegisterDeviceFragment : Fragment() {

    private var _binding: FragmentRegisterDeviceBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: RegisterDeviceViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentRegisterDeviceBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupToolbar()
        setupInputListeners()
        setupSubmitButton()
        observeUiState()
    }

    private fun setupToolbar() {
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigateUp()
        }
    }

    private fun setupInputListeners() {
        binding.etDeviceId.addTextChangedListener { text ->
            viewModel.updateDeviceId(text.toString())
        }
        binding.etDeviceType.addTextChangedListener { text ->
            viewModel.updateType(text.toString())
        }
        binding.etDeviceModel.addTextChangedListener { text ->
            viewModel.updateModel(text.toString())
        }
    }

    private fun setupSubmitButton() {
        binding.btnRegister.setOnClickListener {
            viewModel.registerDevice()
        }
    }

    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                binding.btnRegister.isEnabled = !state.isLoading
                binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE

                state.error?.let { error ->
                    Snackbar.make(binding.root, error, Snackbar.LENGTH_LONG).show()
                    viewModel.clearError()
                }

                if (state.isSuccess) {
                    Snackbar.make(binding.root, "Device registered successfully", Snackbar.LENGTH_SHORT).show()
                    findNavController().navigateUp()
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
