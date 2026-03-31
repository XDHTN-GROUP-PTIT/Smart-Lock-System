package com.example.authenx.presentation.ui.mainapp.enroll_biometric

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.usecase.EnrollFingerprintUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class EnrollBiometricViewModel @Inject constructor(
    private val enrollFingerprintUseCase: EnrollFingerprintUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(EnrollBiometricUiState())
    val uiState: StateFlow<EnrollBiometricUiState> = _uiState.asStateFlow()

    fun enrollFingerprint(userId: String, deviceId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isEnrolling = true,
                error = null,
                enrollmentStatus = "Sending enrollment command to device..."
            )

            enrollFingerprintUseCase(userId, deviceId)
                .onSuccess { response ->
                    _uiState.value = _uiState.value.copy(
                        isEnrolling = true,
                        success = false,
                        fingerprintId = response.fingerprintId,
                        enrollmentStatus = response.note ?: "Please place finger on sensor",
                        waitingForEsp = true
                    )
                }
                .onFailure { error ->
                    _uiState.value = _uiState.value.copy(
                        isEnrolling = false,
                        error = error.message ?: "Enrollment failed"
                    )
                }
        }
    }
    
    fun onEnrollmentComplete() {
        _uiState.value = _uiState.value.copy(
            isEnrolling = false,
            success = true,
            waitingForEsp = false,
            enrollmentStatus = "Fingerprint enrolled successfully! ✅"
        )
    }
    
    fun onEnrollmentFailed(errorMessage: String) {
        _uiState.value = _uiState.value.copy(
            isEnrolling = false,
            waitingForEsp = false,
            error = errorMessage
        )
    }

    fun resetState() {
        _uiState.value = EnrollBiometricUiState()
    }
}

data class EnrollBiometricUiState(
    val isEnrolling: Boolean = false,
    val success: Boolean = false,
    val error: String? = null,
    val fingerprintId: Int? = null,
    val enrollmentStatus: String = "",
    val waitingForEsp: Boolean = false
)
