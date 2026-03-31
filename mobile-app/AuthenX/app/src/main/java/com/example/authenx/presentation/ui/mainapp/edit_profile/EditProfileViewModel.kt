package com.example.authenx.presentation.ui.mainapp.edit_profile

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.User
import com.example.authenx.domain.usecase.GetUserInfoUseCase
import com.example.authenx.domain.usecase.UpdateProfileUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class EditProfileUiState(
    val isLoading: Boolean = false,
    val user: User? = null,
    val error: String? = null,
    val success: Boolean = false
)

@HiltViewModel
class EditProfileViewModel @Inject constructor(
    private val getUserInfoUseCase: GetUserInfoUseCase,
    private val updateProfileUseCase: UpdateProfileUseCase,
    private val authManager: AuthManager
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(EditProfileUiState())
    val uiState: StateFlow<EditProfileUiState> = _uiState.asStateFlow()
    
    fun loadUserData(userId: String?) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            
            try {
                // userId parameter is ignored - always loads current user
                val user = getUserInfoUseCase()

                Log.d("EditProfileViewModel", "Loaded user: $user")
                
                if (user != null) {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            user = user
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            error = "Failed to load user data"
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = e.message ?: "Unknown error"
                    )
                }
            }
        }
    }
    
    fun updateProfile(
        userId: String?,
        fullName: String,
        email: String,
        phone: String?,
        oldPassword: String?,
        newPassword: String?,
        confirmPassword: String?
    ) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            
            try {
                val updates = mutableMapOf<String, Any>(
                    "fullName" to fullName,
                    "email" to email
                )
                
                phone?.let { updates["phone"] = it }
                
                // Add password fields if changing password
                if (!oldPassword.isNullOrEmpty() && !newPassword.isNullOrEmpty()) {
                    updates["oldPassword"] = oldPassword
                    updates["newPassword"] = newPassword
                    updates["confirmPassword"] = confirmPassword ?: ""
                }
                
                val success = updateProfileUseCase(updates)
                
                if (success) {
                    // Update local auth data if editing own profile
                    if (userId == null || userId == authManager.getUserId()) {
                        authManager.saveUserInfo(
                            userId = authManager.getUserId() ?: "",
                            email = email,
                            name = fullName,
                            role = authManager.getUserRole() ?: ""
                        )
                    }
                    
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            success = true
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            error = "Failed to update profile"
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        error = e.message ?: "Update failed"
                    )
                }
            }
        }
    }
    
    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }
}
