package com.example.authenx.presentation.ui.auth.login

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.authenx.BuildConfig
import com.example.authenx.R
import com.example.authenx.data.local.AuthManager
import com.example.authenx.databinding.FragmentLoginBinding
import com.example.authenx.service.SocketService
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class LoginFragment : Fragment() {

    private var _binding: FragmentLoginBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: LoginViewModel by viewModels()
    
    @Inject
    lateinit var authManager: AuthManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentLoginBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val savedStateHandle = findNavController().currentBackStackEntry?.savedStateHandle

        savedStateHandle?.getLiveData<String>("email")?.observe(viewLifecycleOwner) {
            binding.etEmail.setText(it)
        }
        savedStateHandle?.getLiveData<String>("password")?.observe(viewLifecycleOwner) {
            binding.etPassword.setText(it)
        }

        setOnClickListener()
    }

    private fun setOnClickListener() {
        with(binding) {
            btnLogin.setOnClickListener {
                handleLogin()
            }
        }
    }
    
    private fun handleLogin() {
        val email = binding.etEmail.text.toString().trim()
        val password = binding.etPassword.text.toString().trim()
        
        // Validation
        if (email.isEmpty()) {
            binding.etEmail.error = "Email is required"
            return
        }
        
        if (password.isEmpty()) {
            binding.etPassword.error = "Password is required"
            return
        }
        
        // Show loading
        showLoading(true)
        
        // Call API
        lifecycleScope.launch {
            try {
                val response = viewModel.login(email, password)
                showLoading(false)
                if (response.success && response.token != null) {
                    // Save token and user info
                    authManager.saveToken(response.token)

                    response.user?.let { user ->
                        authManager.saveUserInfo(
                            userId = user.id,
                            email = user.email,
                            name = user.fullName,
                            role = user.role
                        )
                    }
                    
                    // Show success message
                    Toast.makeText(
                        requireContext(),
                        "Login successful!",
                        Toast.LENGTH_SHORT
                    ).show()

                    // Start socket service for real-time notifications with userId and role
                    val serverUrl = BuildConfig.SERVER_URL
                    val userId = response.user?.id
                    val role = response.user?.role
                    SocketService.start(requireContext(), serverUrl, response.token, userId, role)

                    findNavController().navigate(R.id.action_loginFragment_to_homeFragment)
                } else {
                    Toast.makeText(
                        requireContext(),
                        response.message ?: "Login failed",
                        Toast.LENGTH_SHORT
                    ).show()
                }
                
            } catch (e: Exception) {
                showLoading(false)
                Toast.makeText(
                    requireContext(),
                    "Error: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
                Log.d("LoginFragment", "Error: ${e.message}")
            }
        }
    }
    
    private fun showLoading(isLoading: Boolean) {
        binding.btnLogin.isEnabled = !isLoading
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}