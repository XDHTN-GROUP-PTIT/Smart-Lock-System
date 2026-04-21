package com.example.authenx.presentation.ui.mainapp.face_authen

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.model.FaceRecognitionState
import com.example.authenx.domain.usecase.CheckActionUseCase
import com.example.authenx.domain.usecase.UnlockByFaceUseCase
import com.example.authenx.domain.usecase.VerifyFaceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class FaceAuthenUiState(
    val state: FaceRecognitionState = FaceRecognitionState.IDLE,
    val instruction: String = "Nhấn nút chụp để bắt đầu",
    val isLoading: Boolean = false,
    val error: String? = null,
    val personName: String? = null,
    val similarity: Double? = null,
    val requiredDirection: String? = null,
    val initialX: Double? = null,
    val isUnlockSuccess: Boolean = false,
    val unlockMessage: String? = null
)

@HiltViewModel
class FaceAuthenViewModel @Inject constructor(
    private val verifyFaceUseCase: VerifyFaceUseCase,
    private val checkActionUseCase: CheckActionUseCase,
    private val unlockByFaceUseCase: UnlockByFaceUseCase
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(FaceAuthenUiState())
    val uiState: StateFlow<FaceAuthenUiState> = _uiState.asStateFlow()
    
    fun capturePressed() {
        when (_uiState.value.state) {
            FaceRecognitionState.IDLE -> {
                _uiState.value = _uiState.value.copy(
                    state = FaceRecognitionState.CAPTURING_FRONT,
                    instruction = "Taking photos..."
                )
            }
            FaceRecognitionState.WAITING_ACTION -> {
                _uiState.value = _uiState.value.copy(
                    state = FaceRecognitionState.CAPTURING_ACTION,
                    instruction = "Taking action shots..."
                )
            }
            else -> {}
        }
    }
    
    fun processFrontFace(imageBase64: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                state = FaceRecognitionState.VERIFYING,
                isLoading = true,
                instruction = "Authenticating face..."
            )
            
            verifyFaceUseCase(imageBase64).fold(
                onSuccess = { response ->
                    if (response.verified) {
                        val direction = listOf("left", "right").random()
                        _uiState.value = _uiState.value.copy(
                            state = FaceRecognitionState.WAITING_ACTION,
                            isLoading = false,
                            personName = response.person,
                            similarity = response.similarity,
                            initialX = response.initialX,
                            requiredDirection = direction,
                            instruction = "Hello ${response.person}! (${(response.similarity * 100).toInt()}%)\nNow turn your head ${if (direction == "left") "LEFT" else "RIGHT"}"
                        )
                    } else {
                        _uiState.value = _uiState.value.copy(
                            state = FaceRecognitionState.ERROR,
                            isLoading = false,
                            error = "Unable to recognize face",
                            instruction = "No face found in the system"
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.value = _uiState.value.copy(
                        state = FaceRecognitionState.ERROR,
                        isLoading = false,
                        error = error.message ?: "Connection error",
                        instruction = "Can't connect to AI server"
                    )
                }
            )
        }
    }
    
    fun processActionFace(imageBase64: String) {
        viewModelScope.launch {
            val initialX = _uiState.value.initialX ?: return@launch
            val direction = _uiState.value.requiredDirection ?: return@launch
            
            _uiState.value = _uiState.value.copy(
                state = FaceRecognitionState.CHECKING_ACTION,
                isLoading = true,
                instruction = "Checking for liveness..."
            )
            
            checkActionUseCase(imageBase64, initialX, direction).fold(
                onSuccess = { response ->
                    if (response.moved) {
                        _uiState.value = _uiState.value.copy(
                            state = FaceRecognitionState.SUCCESS,
                            isLoading = false,
                            instruction = "Authentication successful!",
                            isUnlockSuccess = true
                        )
                    } else {
                        _uiState.value = _uiState.value.copy(
                            state = FaceRecognitionState.ERROR,
                            isLoading = false,
                            error = "You haven't turned in the right direction",
                            instruction = "Please try again"
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.value = _uiState.value.copy(
                        state = FaceRecognitionState.ERROR,
                        isLoading = false,
                        error = error.message ?: "Connection error",
                        instruction = "Cannot check action"
                    )
                }
            )
        }
    }
    
    fun unlockDevice(deviceId: String, token: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                instruction = "Unlocking device..."
            )
            
            unlockByFaceUseCase(deviceId, token).fold(
                onSuccess = { response ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        instruction = if (response.success) "Device unlocked successfully!" else response.message,
                        unlockMessage = response.message
                    )
                },
                onFailure = { error ->
                    _uiState.value = _uiState.value.copy(
                        state = FaceRecognitionState.ERROR,
                        isLoading = false,
                        error = error.message ?: "Failed to unlock device",
                        instruction = "Cannot unlock device"
                    )
                }
            )
        }
    }
    
    fun reset() {
        _uiState.value = FaceAuthenUiState()
    }
}