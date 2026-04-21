package com.example.authenx.presentation.ui.mainapp.device

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.usecase.RegisterDeviceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class RegisterDeviceUiState(
    val isLoading: Boolean = false,
    val isSuccess: Boolean = false,
    val error: String? = null,
    val deviceId: String = "",
    val type: String = "smart_lock",
    val model: String = "ESP32_v1"
)

@HiltViewModel
class RegisterDeviceViewModel @Inject constructor(
    private val registerDeviceUseCase: RegisterDeviceUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegisterDeviceUiState())
    val uiState: StateFlow<RegisterDeviceUiState> = _uiState.asStateFlow()

    fun updateDeviceId(deviceId: String) {
        _uiState.value = _uiState.value.copy(deviceId = deviceId)
    }

    fun updateType(type: String) {
        _uiState.value = _uiState.value.copy(type = type)
    }

    fun updateModel(model: String) {
        _uiState.value = _uiState.value.copy(model = model)
    }

    fun registerDevice() {
        val state = _uiState.value
        
        // Validation
        if (state.deviceId.isBlank()) {
            _uiState.value = state.copy(error = "Device ID is required")
            return
        }

        if (state.type.isBlank()) {
            _uiState.value = state.copy(error = "Device Type is required")
            return
        }

        if (state.model.isBlank()) {
            _uiState.value = state.copy(error = "Device Model is required")
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(isLoading = true, error = null)
            
            val result = registerDeviceUseCase(
                deviceId = state.deviceId,
                type = state.type,
                model = state.model
            )

            result.fold(
                onSuccess = { device ->
                    _uiState.value = RegisterDeviceUiState(isSuccess = true)
                },
                onFailure = { error ->
                    _uiState.value = state.copy(
                        isLoading = false,
                        error = error.message ?: "Failed to register device"
                    )
                }
            )
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}
