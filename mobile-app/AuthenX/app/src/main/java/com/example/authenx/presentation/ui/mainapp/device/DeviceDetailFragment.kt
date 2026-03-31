package com.example.authenx.presentation.ui.mainapp.device

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.example.authenx.R
import com.example.authenx.databinding.FragmentDeviceDetailBinding
import com.example.authenx.domain.model.Device
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@AndroidEntryPoint
class DeviceDetailFragment : Fragment() {

    private var _binding: FragmentDeviceDetailBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: DeviceDetailViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentDeviceDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupToolbar()
        observeUiState()
        setupActionButtons()
    }

    private fun setupToolbar() {
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigateUp()
        }
    }

    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                state.device?.let { device ->
                    displayDeviceDetails(device)
                }

                state.error?.let { error ->
                    Snackbar.make(binding.root, error, Snackbar.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun displayDeviceDetails(device: Device) {
        binding.apply {
            tvDeviceIdValue.text = device.deviceId
            tvTypeValue.text = device.type
            tvModelValue.text = device.model
            tvStatusValue.text = device.status.uppercase()
            
            // Set status color
            val statusColor = when (device.status.lowercase()) {
                "online" -> R.color.green_status
                "offline" -> R.color.gray_status
                "pending" -> R.color.orange_status
                "blocked" -> R.color.red_status
                else -> R.color.gray_status
            }
            tvStatusValue.setTextColor(requireContext().getColor(statusColor))
            
            // Format timestamps - handle both ISO string and direct display
            tvCreatedAtValue.text = device.createdAt?.let { 
                formatTimestamp(it)
            } ?: "N/A"
            tvLastActiveValue.text = device.lastSeen?.let { 
                formatTimestamp(it)
            } ?: "N/A"
        }
    }
    
    private fun formatTimestamp(timestamp: String): String {
        return try {
            // Try to parse ISO 8601 format from MongoDB (e.g., "2024-12-07T01:30:00.000Z")
            val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault())
            isoFormat.timeZone = java.util.TimeZone.getTimeZone("UTC")
            val date = isoFormat.parse(timestamp)
            
            val displayFormat = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
            date?.let { displayFormat.format(it) } ?: timestamp
        } catch (e: Exception) {
            // If parsing fails, return the original string
            timestamp
        }
    }

    private fun setupActionButtons() {
        binding.btnUnlockByFace.setOnClickListener {
            // Navigate to face authentication for unlock
            val deviceId = viewModel.uiState.value.deviceId
            if (deviceId != null) {
                val action = DeviceDetailFragmentDirections
                    .actionDeviceDetailFragmentToFaceAuthenFragment(deviceId)
                findNavController().navigate(action)
            } else {
                Snackbar.make(binding.root, "Device ID not found", Snackbar.LENGTH_SHORT).show()
            }
        }

        binding.btnEnrollFingerprint.setOnClickListener {
            // Use deviceId from uiState - it's passed from DeviceListFragment
            val deviceId = viewModel.uiState.value.deviceId
            if (deviceId != null) {
                val bundle = androidx.core.os.bundleOf("deviceId" to deviceId)
                findNavController().navigate(
                    R.id.action_deviceDetailFragment_to_selectUserFragment,
                    bundle
                )
            } else {
                Snackbar.make(binding.root, "Device ID not found", Snackbar.LENGTH_SHORT).show()
            }
        }

        binding.btnEnrollRfid.setOnClickListener {
            // Navigate to select user for RFID enrollment
            val deviceId = viewModel.uiState.value.deviceId
            if (deviceId != null) {
                val bundle = androidx.core.os.bundleOf("deviceId" to deviceId)
                findNavController().navigate(
                    R.id.action_deviceDetailFragment_to_selectUserForRfidFragment,
                    bundle
                )
            } else {
                Snackbar.make(binding.root, "Device ID not found", Snackbar.LENGTH_SHORT).show()
            }
        }

        binding.btnViewLogs.setOnClickListener {
            // TODO: Navigate to device logs
            Snackbar.make(binding.root, "View logs coming soon", Snackbar.LENGTH_SHORT).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
