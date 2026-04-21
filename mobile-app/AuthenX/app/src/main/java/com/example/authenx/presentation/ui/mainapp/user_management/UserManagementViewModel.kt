package com.example.authenx.presentation.ui.mainapp.user_management

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.User
import com.example.authenx.domain.usecase.DeleteUserUseCase
import com.example.authenx.domain.usecase.DeleteFingerprintUseCase
import com.example.authenx.domain.usecase.DeleteRfidUseCase
import com.example.authenx.domain.usecase.GetAllUsersUseCase
import com.example.authenx.data.remote.socket.SocketManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

data class UserManagementUiState(
    val users: List<User> = emptyList(),
    val filteredUsers: List<User> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null,
    val searchQuery: String = "",
    val filterType: FilterType = FilterType.ALL,
    val currentUserRole: String = ""
)

enum class FilterType {
    ALL, FINGERPRINT, FACE, RFID
}

@HiltViewModel
class UserManagementViewModel @Inject constructor(
    private val getAllUsersUseCase: GetAllUsersUseCase,
    private val deleteUserUseCase: DeleteUserUseCase,
    private val deleteFingerprintUseCase: DeleteFingerprintUseCase,
    private val deleteRfidUseCase: DeleteRfidUseCase,
    private val authManager: AuthManager,
    private val socketManager: SocketManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(UserManagementUiState(isLoading = true))
    val uiState: StateFlow<UserManagementUiState> = _uiState.asStateFlow()

    init {
        val currentRole = authManager.getUserRole() ?: ""
        _uiState.update { it.copy(currentUserRole = currentRole) }
        observeUsers()
        observeSocketEvents()
    }

    private fun observeSocketEvents() {
        viewModelScope.launch {
            socketManager.onUserChanged().collect {
                android.util.Log.d("UserManagementVM", "🔔 Socket event: User list changed, refreshing...")
                // Trigger refresh by re-collecting users
                observeUsers()
            }
        }
    }

    private fun observeUsers() {
        viewModelScope.launch {
            getAllUsersUseCase()
                .catch { exception ->
                    android.util.Log.e("UserManagementVM", "Error loading users", exception)
                    _uiState.update { 
                        it.copy(
                            isLoading = false, 
                            error = exception.message ?: "Unknown error"
                        ) 
                    }
                }
                .collect { users ->
                    android.util.Log.d("UserManagementVM", "Received ${users.size} users from API")
                    users.forEach { user ->
                        android.util.Log.d("UserManagementVM", "User: ${user.fullName}, Role: ${user.role}")
                    }
                    
                    _uiState.update { currentState ->
                        val filteredByRole = filterUsersByRole(users, currentState.currentUserRole)
                        android.util.Log.d("UserManagementVM", "After role filter (${currentState.currentUserRole}): ${filteredByRole.size} users")
                        
                        currentState.copy(
                            users = filteredByRole,
                            filteredUsers = filterUsers(
                                filteredByRole,
                                currentState.searchQuery,
                                currentState.filterType
                            ),
                            isLoading = false,
                            error = null
                        )
                    }
                }
        }
    }
    
    private fun filterUsersByRole(users: List<User>, currentRole: String): List<User> {
        return when (currentRole) {
            "admin" -> {
                users.filter { it.role == "user_manager" }
            }
            "user_manager" -> {
                users.filter { it.role == "user" }
            }
            else -> emptyList()
        }
    }

    fun searchUsers(query: String) {
        _uiState.update { currentState ->
            currentState.copy(
                searchQuery = query,
                filteredUsers = filterUsers(
                    currentState.users,
                    query,
                    currentState.filterType
                )
            )
        }
    }

    fun setFilter(filterType: FilterType) {
        _uiState.update { currentState ->
            currentState.copy(
                filterType = filterType,
                filteredUsers = filterUsers(
                    currentState.users,
                    currentState.searchQuery,
                    filterType
                )
            )
        }
    }

    fun deleteUser(userId: String) {
        viewModelScope.launch {
            try {
                android.util.Log.d("UserManagementVM", "Deleting user: $userId")
                val success = deleteUserUseCase(userId)
                if (success) {
                    android.util.Log.d("UserManagementVM", "✅ User deleted successfully")
                } else {
                    android.util.Log.e("UserManagementVM", "❌ Failed to delete user")
                    _uiState.update { it.copy(error = "Failed to delete user") }
                }
            } catch (e: Exception) {
                android.util.Log.e("UserManagementVM", "❌ Error deleting user: ${e.message}")
                _uiState.update { it.copy(error = e.message ?: "Failed to delete user") }
            }
        }
    }
    
    fun deleteFingerprint(fingerprintId: String, userId: String, deviceId: String?) {
        viewModelScope.launch {
            try {
                val request = com.example.authenx.domain.model.DeleteFingerprintRequest(
                    fingerprintId = fingerprintId,
                    userId = userId,
                    deviceId = deviceId ?: ""
                )
                val response = deleteFingerprintUseCase(request)
                if (response.success) {
                    _uiState.update { it.copy(error = "Fingerprint deleted successfully") }
                } else {
                    _uiState.update { it.copy(error = response.message ?: "Failed to delete fingerprint") }
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message ?: "Delete fingerprint failed") }
            }
        }
    }
    
    fun deleteRfid(uid: String, userId: String) {
        viewModelScope.launch {
            try {
                val request = com.example.authenx.domain.model.DeleteRfidRequest(
                    uid = uid,
                    userId = userId
                )
                val response = deleteRfidUseCase(request)
                if (response.success) {
                    _uiState.update { it.copy(error = "RFID card deleted successfully") }
                } else {
                    _uiState.update { it.copy(error = response.message ?: "Failed to delete RFID card") }
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message ?: "Delete RFID failed") }
            }
        }
    }

    private fun filterUsers(
        users: List<User>,
        query: String,
        filterType: FilterType
    ): List<User> {
        var filtered = users

        // Apply search filter
        if (query.isNotEmpty()) {
            filtered = filtered.filter { user ->
                user.fullName.contains(query, ignoreCase = true) ||
                user.email.contains(query, ignoreCase = true) ||
                user.phone.contains(query, ignoreCase = true)
            }
        }

        // Apply type filter
        filtered = when (filterType) {
            FilterType.ALL -> filtered
            FilterType.FINGERPRINT -> filtered // TODO: Add fingerprint check
            FilterType.FACE -> filtered // TODO: Add face check
            FilterType.RFID -> filtered // TODO: Add RFID check
        }

        return filtered
    }
}
