package com.example.authenx.presentation.ui.auth.register

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.model.Organization
import com.example.authenx.domain.model.RegisterRequest
import com.example.authenx.domain.usecase.GetAllOrganizationsUseCase
import com.example.authenx.domain.usecase.RegisterUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val registerUseCase: RegisterUseCase,
    private val getAllOrganizationsUseCase: GetAllOrganizationsUseCase
) : ViewModel() {
    
    private val _organizations = MutableStateFlow<List<Organization>>(emptyList())
    val organizations: StateFlow<List<Organization>> = _organizations.asStateFlow()
    
    private val _isLoadingOrgs = MutableStateFlow(false)
    val isLoadingOrgs: StateFlow<Boolean> = _isLoadingOrgs.asStateFlow()
    
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    
    fun loadOrganizations() {
        viewModelScope.launch {
            _isLoadingOrgs.value = true
            _error.value = null
            try {
                val response = getAllOrganizationsUseCase()
                if (response.code == 200) {
                    _organizations.value = response.data ?: emptyList()
                } else {
                    _error.value = response.message ?: "Failed to load organizations"
                }
            } catch (e: Exception) {
                _organizations.value = emptyList()
                _error.value = e.message ?: "Network error"
            } finally {
                _isLoadingOrgs.value = false
            }
        }
    }
    
    suspend fun register(email: String, password: String, confirmPassword: String, fullName: String, phone: String?, orgId: String) = 
        registerUseCase(RegisterRequest(email, password, fullName, confirmPassword, phone, orgId))
}