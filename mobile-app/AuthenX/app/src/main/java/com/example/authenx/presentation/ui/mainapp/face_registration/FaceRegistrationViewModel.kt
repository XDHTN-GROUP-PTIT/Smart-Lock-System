package com.example.authenx.presentation.ui.mainapp.face_registration

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.usecase.DeleteFaceUseCase
import com.example.authenx.domain.usecase.RegisterFaceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class FaceRegistrationState {
    IDLE,
    CAPTURING,
    REGISTERING,
    SUCCESS,
    ERROR
}

data class FaceRegistrationUiState(
    val state: FaceRegistrationState = FaceRegistrationState.IDLE,
    val message: String = "",
    val isLoading: Boolean = false,
    val faceId: String? = null,
    val capturedImage: String? = null
)

@HiltViewModel
class FaceRegistrationViewModel @Inject constructor(
    private val registerFaceUseCase: RegisterFaceUseCase,
    private val deleteFaceUseCase: DeleteFaceUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(FaceRegistrationUiState())
    val uiState: StateFlow<FaceRegistrationUiState> = _uiState.asStateFlow()

    fun capturePressed() {
        _uiState.value = _uiState.value.copy(
            state = FaceRegistrationState.CAPTURING
        )
    }

    fun registerFace(imageBase64: String, userId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                state = FaceRegistrationState.REGISTERING,
                isLoading = true,
                message = "Registering face...",
                capturedImage = imageBase64
            )

            registerFaceUseCase(imageBase64, userId).fold(
                onSuccess = { response ->
                    if (response.status == "success") {
                        _uiState.value = _uiState.value.copy(
                            state = FaceRegistrationState.SUCCESS,
                            isLoading = false,
                            message = response.message,
                            faceId = response.faceId
                        )
                    } else {
                        _uiState.value = _uiState.value.copy(
                            state = FaceRegistrationState.ERROR,
                            isLoading = false,
                            message = response.message
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.value = _uiState.value.copy(
                        state = FaceRegistrationState.ERROR,
                        isLoading = false,
                        message = error.message ?: "Connection error. Please try again."
                    )
                }
            )
        }
    }

    fun deleteFace(userId: String, onSuccess: () -> Unit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                message = "Deleting face..."
            )

            deleteFaceUseCase(userId).fold(
                onSuccess = { response ->
                    if (response.status == "success") {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            message = response.message
                        )
                        onSuccess()
                    } else {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            message = response.message
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        message = error.message ?: "Error deleting face"
                    )
                }
            )
        }
    }

    fun reset() {
        _uiState.value = FaceRegistrationUiState()
    }
}
