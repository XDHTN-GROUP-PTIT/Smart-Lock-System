package com.example.authenx.presentation.ui.mainapp.select_user

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.domain.model.User
import com.example.authenx.domain.usecase.GetAllUsersUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SelectUserUiState(
    val isLoading: Boolean = false,
    val users: List<User> = emptyList(),
    val filteredUsers: List<User> = emptyList(),
    val searchQuery: String = "",
    val error: String? = null
)

@HiltViewModel
class SelectUserViewModel @Inject constructor(
    private val getAllUsersUseCase: GetAllUsersUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(SelectUserUiState())
    val uiState: StateFlow<SelectUserUiState> = _uiState.asStateFlow()

    init {
        loadUsers()
    }

    private fun loadUsers() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)
            
            try {
                getAllUsersUseCase().collect { users ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        users = users,
                        filteredUsers = users
                    )
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = e.message ?: "Failed to load users"
                )
            }
        }
    }

    fun searchUsers(query: String) {
        _uiState.value = _uiState.value.copy(searchQuery = query)
        
        val filtered = if (query.isBlank()) {
            _uiState.value.users
        } else {
            _uiState.value.users.filter { user ->
                user.fullName.contains(query, ignoreCase = true) ||
                user.email.contains(query, ignoreCase = true) ||
                user.phone.contains(query, ignoreCase = true)
            }
        }
        
        _uiState.value = _uiState.value.copy(filteredUsers = filtered)
    }

    fun refresh() {
        loadUsers()
    }
}
