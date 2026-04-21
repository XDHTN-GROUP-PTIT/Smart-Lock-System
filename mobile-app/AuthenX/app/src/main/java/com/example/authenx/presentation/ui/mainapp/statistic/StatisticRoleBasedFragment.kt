package com.example.authenx.presentation.ui.mainapp.statistic

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.authenx.databinding.FragmentStatisticRoleBasedBinding
import com.example.authenx.presentation.ui.mainapp.statistic.adapter.DeviceStatsAdapter
import com.example.authenx.presentation.ui.mainapp.statistic.adapter.OrganizationStatsAdapter
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class StatisticRoleBasedFragment : Fragment() {

    private var _binding: FragmentStatisticRoleBasedBinding? = null
    private val binding get() = _binding!!
    private val viewModel: StatisticViewModel by viewModels()

    companion object {
        private const val TAG = "StatisticRoleBased"
    }

    private val deviceStatsAdapter by lazy {
        DeviceStatsAdapter { device ->
            // Handle device click - navigate to device detail
            Toast.makeText(requireContext(), "Device: ${device.deviceName}", Toast.LENGTH_SHORT).show()
        }
    }

    private val organizationStatsAdapter by lazy {
        OrganizationStatsAdapter { org ->
            // Handle organization click
            Toast.makeText(requireContext(), "Organization: ${org.orgName}", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentStatisticRoleBasedBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setupRecyclerViews()
        setupClickListeners()
        observeUiState()
    }

    private fun setupRecyclerViews() {
        with(binding) {
            rvDeviceStats.apply {
                layoutManager = LinearLayoutManager(requireContext())
                adapter = deviceStatsAdapter
            }

            rvOrganizationStats.apply {
                layoutManager = LinearLayoutManager(requireContext())
                adapter = organizationStatsAdapter
            }
        }
    }

    private fun setupClickListeners() {
        with(binding) {
            btnBack.setOnClickListener {
                findNavController().navigateUp()
            }

            btnRefresh.setOnClickListener {
                viewModel.refresh()
            }
        }
    }

    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    Log.d(TAG, "UI State: isLoading=${state.isLoading}, role=${state.userRole}, error=${state.error}")
                    Log.d(TAG, "User Manager Stats: ${state.userManagerStats}")
                    Log.d(TAG, "Admin Stats: ${state.adminStats}")
                    
                    binding.progressBar.isVisible = state.isLoading
                    
                    // Show/hide views based on role
                    when (state.userRole) {
                        "admin" -> {
                            Log.d(TAG, "Showing admin view")
                            state.adminStats?.let { 
                                updateAdminView(it)
                            } ?: run {
                                Log.w(TAG, "Admin stats is null, hiding views")
                                binding.layoutAdminStats.isVisible = false
                                binding.layoutUserManagerStats.isVisible = false
                            }
                        }
                        "user_manager" -> {
                            Log.d(TAG, "Showing user_manager view")
                            state.userManagerStats?.let { 
                                updateUserManagerView(it)
                            } ?: run {
                                Log.w(TAG, "User manager stats is null, hiding views")
                                binding.layoutUserManagerStats.isVisible = false
                                binding.layoutAdminStats.isVisible = false
                            }
                        }
                        else -> {
                            Log.d(TAG, "Unknown role or no role, hiding all views")
                            // Default or error state
                            binding.layoutUserManagerStats.isVisible = false
                            binding.layoutAdminStats.isVisible = false
                        }
                    }
                    
                    state.error?.let { error ->
                        Log.e(TAG, "Error: $error")
                        Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun updateUserManagerView(stats: com.example.authenx.domain.model.UserManagerStatsResponse) {
        Log.d(TAG, "Updating user manager view with data: ${stats.data}")
        Log.d(TAG, "layoutUserManagerStats visibility before: ${binding.layoutUserManagerStats.visibility}")
        
        with(binding) {
            // Ensure view is visible
            layoutUserManagerStats.visibility = View.VISIBLE
            layoutAdminStats.visibility = View.GONE
            
            tvTotalDevices.text = stats.data.totalDevices.toString()
            tvTotalChildren.text = stats.data.totalChildren.toString()
            tvTotalAlerts.text = stats.data.totalSecurityAlerts.toString()
            tvUnreadNotifications.text = stats.data.unreadNotifications.toString()
            
            Log.d(TAG, "Set text values - Devices: ${stats.data.totalDevices}, Children: ${stats.data.totalChildren}")
            Log.d(TAG, "Device stats size: ${stats.data.deviceStats.size}")
            
            deviceStatsAdapter.submitList(stats.data.deviceStats)
            
            Log.d(TAG, "layoutUserManagerStats visibility after: ${layoutUserManagerStats.visibility}")
        }
    }

    private fun updateAdminView(stats: com.example.authenx.domain.model.AdminStatsResponse) {
        Log.d(TAG, "Updating admin view with data: ${stats.data}")
        with(binding) {
            tvTotalOrganizations.text = stats.data.totalOrganizations.toString()
            
            Log.d(TAG, "Organizations size: ${stats.data.organizations.size}")
            organizationStatsAdapter.submitList(stats.data.organizations)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
