package com.example.authenx.presentation.ui.splash

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.authenx.BuildConfig
import com.example.authenx.R
import com.example.authenx.data.local.AuthManager
import com.example.authenx.databinding.FragmentSplashBinding
import com.example.authenx.service.SocketService
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SplashFragment : Fragment() {

    private var _binding: FragmentSplashBinding? = null
    private val binding get() = _binding!!
    
    @Inject
    lateinit var authManager: AuthManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSplashBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        lifecycleScope.launch {
            delay(1500)
            checkAuthStatus()
        }
    }

    private fun checkAuthStatus() {
        val token = authManager.getToken()
        
        if (!token.isNullOrEmpty() && token.length > 10) {
            // Token exists and looks valid, try to go to home
            val serverUrl = BuildConfig.SERVER_URL
            val userId = authManager.getUserId()
            val role = authManager.getUserRole()
            SocketService.start(requireContext(), serverUrl, token, userId, role)
            findNavController().navigate(R.id.action_splashFragment_to_homeFragment)
        } else {
            // No token or invalid token, go to login
            findNavController().navigate(R.id.action_splashFragment_to_loginFragment)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
