package com.example.authenx.presentation.ui.mainapp.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.example.authenx.BuildConfig
import com.example.authenx.R
import com.example.authenx.data.local.AuthManager
import com.example.authenx.data.remote.socket.SocketManager
import com.example.authenx.databinding.FragmentHomeBinding
import com.example.authenx.service.SocketService
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    
    @Inject
    lateinit var authManager: AuthManager
    
    @Inject
    lateinit var socketManager: SocketManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupRoleBasedUI()
        setOnClickListener()
        
        // Debug logging
        android.util.Log.d("HomeFragment", "📱 User ID: ${authManager.getUserId()}")
        android.util.Log.d("HomeFragment", "📱 User Role: ${authManager.getUserRole()}")
        android.util.Log.d("HomeFragment", "📱 Socket connected: ${socketManager.isConnected()}")
    }
    
    private fun setupRoleBasedUI() {
        val userRole = authManager.getUserRole()
        
        when (userRole) {
            "admin" -> setupAdminUI()
            "user_manager" -> setupUserManagerUI()
            else -> setupDefaultUI()
        }
    }
    
    private fun setupAdminUI() {
        // Admin can see everything
        binding.btnRegisterFace.visibility = View.GONE
        binding.btnStatistic.visibility = View.VISIBLE
        binding.btnManageUsers.visibility = View.VISIBLE
        binding.btnCreateOrganization.visibility = View.VISIBLE
        binding.btnUpdate.visibility = View.VISIBLE
        binding.btnProfile.visibility = View.VISIBLE
    }
    
    private fun setupUserManagerUI() {
        // user_manager can manage users, view statistics, enroll biometrics
        binding.btnRegisterFace.visibility = View.VISIBLE
        binding.btnStatistic.visibility = View.VISIBLE
        binding.btnManageUsers.visibility = View.VISIBLE
        binding.btnCreateOrganization.visibility = View.GONE // Admin only
        binding.btnManageDevices.visibility = View.VISIBLE
        binding.btnUpdate.visibility = View.VISIBLE
        binding.btnProfile.visibility = View.VISIBLE
    }
    
    private fun setupDefaultUI() {
        // Default user - minimal access
        binding.btnRegisterFace.visibility = View.GONE
        binding.btnStatistic.visibility = View.GONE
        binding.btnManageUsers.visibility = View.GONE
        binding.btnCreateOrganization.visibility = View.GONE
        binding.btnUpdate.visibility = View.GONE
    }

    private fun setOnClickListener() {
        with(binding) {
            btnRegisterFace.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_faceRegistrationFragment)
            }
            btnStatistic.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_statisticFragment)
            }
            btnManageUsers.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_userManagementFragment)
            }
            btnCreateOrganization.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_createOrganizationFragment)
            }
            btnManageDevices.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_deviceListFragment)
            }
            btnProfile.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_editProfileFragment)
            }
            btnUpdate.setOnClickListener {
                findNavController().navigate(R.id.action_homeFragment_to_firmwareUpdateFragment)
            }
            btnLogout.setOnClickListener {
                logout()
            }
        }
    }

    private fun logout() {
        SocketService.stop(requireContext())
        authManager.clearAuth()
        findNavController().navigate(R.id.action_homeFragment_to_loginFragment)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}