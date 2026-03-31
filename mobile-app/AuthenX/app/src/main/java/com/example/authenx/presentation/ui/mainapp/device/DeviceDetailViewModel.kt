package com.example.authenx.presentation.ui.mainapp.device

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.example.authenx.domain.model.Device
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

data class DeviceDetailUiState(
    val device: Device? = null,
    val deviceId: String? = null,
    val isLoading: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class DeviceDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle
) : ViewModel() {

    private val _uiState = MutableStateFlow(DeviceDetailUiState())
    val uiState: StateFlow<DeviceDetailUiState> = _uiState.asStateFlow()

    init {
        // Get device from navigation arguments - either as object or as individual fields
        val existingDevice = savedStateHandle.get<Device>("device")
        
        if (existingDevice != null) {
            _uiState.value = DeviceDetailUiState(
                device = existingDevice,
                deviceId = existingDevice.deviceId
            )
        } else {
            // Reconstruct device from individual fields
            val deviceId = savedStateHandle.get<String>("deviceId")
            val deviceType = savedStateHandle.get<String>("deviceType")
            val deviceModel = savedStateHandle.get<String>("deviceModel")
            val deviceStatus = savedStateHandle.get<String>("deviceStatus")
            val deviceOrgId = savedStateHandle.get<String>("deviceOrgId")
            val deviceLastSeen = savedStateHandle.get<String>("deviceLastSeen")
            val deviceCreatedAt = savedStateHandle.get<String>("deviceCreatedAt")
            
            if (deviceId != null) {
                val device = Device(
                    id = deviceId,
                    deviceId = deviceId,
                    type = deviceType,
                    model = deviceModel,
                    status = deviceStatus ?: "unknown",
                    fwCurrent = null,
                    orgId = deviceOrgId,
                    lastSeen = deviceLastSeen,
                    createdAt = deviceCreatedAt,
                    updatedAt = null
                )
                _uiState.value = DeviceDetailUiState(
                    device = device,
                    deviceId = deviceId
                )
            }
        }
    }
}
