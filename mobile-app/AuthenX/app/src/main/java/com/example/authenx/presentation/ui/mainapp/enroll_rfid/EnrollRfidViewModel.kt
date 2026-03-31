package com.example.authenx.presentation.ui.mainapp.enroll_rfid

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.usecase.EnrollRfidUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class EnrollRfidViewModel @Inject constructor(
    private val enrollRfidUseCase: EnrollRfidUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(EnrollRfidUiState())
    val uiState: StateFlow<EnrollRfidUiState> = _uiState.asStateFlow()

    fun enrollRfid(userId: String, deviceId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isEnrolling = true,
                error = null,
                enrollmentStatus = "Sending enrollment command to device..."
            )

            enrollRfidUseCase(userId, deviceId)
                .onSuccess { response ->
                    _uiState.value = _uiState.value.copy(
                        isEnrolling = true,
                        success = false,
                        enrollmentStatus = response.instruction ?: "Please scan RFID card on reader",
                        waitingForDevice = true
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
    
    fun onEnrollmentComplete(cardUid: String) {
        _uiState.value = _uiState.value.copy(
            isEnrolling = false,
            success = true,
            waitingForDevice = false,
            cardUid = cardUid,
            enrollmentStatus = "RFID card enrolled successfully! ✅"
        )
    }
    
    fun onEnrollmentFailed(errorMessage: String) {
        _uiState.value = _uiState.value.copy(
            isEnrolling = false,
            waitingForDevice = false,
            error = errorMessage
        )
    }

    fun resetState() {
        _uiState.value = EnrollRfidUiState()
    }
}

data class EnrollRfidUiState(
    val isEnrolling: Boolean = false,
    val success: Boolean = false,
    val error: String? = null,
    val cardUid: String? = null,
    val enrollmentStatus: String = "",
    val waitingForDevice: Boolean = false
)
