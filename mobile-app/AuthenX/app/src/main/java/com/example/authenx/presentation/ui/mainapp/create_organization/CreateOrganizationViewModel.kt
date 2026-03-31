package com.example.authenx.presentation.ui.mainapp.create_organization

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.usecase.CreateOrganizationUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CreateOrganizationViewModel @Inject constructor(
    private val createOrganizationUseCase: CreateOrganizationUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(CreateOrganizationUiState())
    val uiState: StateFlow<CreateOrganizationUiState> = _uiState.asStateFlow()

    fun createOrganization(name: String, address: String?) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)

            createOrganizationUseCase(name, address)
                .onSuccess { response ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        success = true,
                        organizationId = response.organization?.id,
                        organizationName = response.organization?.name
                    )
                }
                .onFailure { error ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = error.message ?: "Failed to create organization"
                    )
                }
        }
    }

    fun resetState() {
        _uiState.value = CreateOrganizationUiState()
    }
}

data class CreateOrganizationUiState(
    val isLoading: Boolean = false,
    val success: Boolean = false,
    val error: String? = null,
    val organizationId: String? = null,
    val organizationName: String? = null
)
