package com.example.authenx.data.repository

import com.example.authenx.data.local.AuthManager
import com.example.authenx.data.remote.socket.SocketManager
import com.example.authenx.data.remote.source.UserDataSource
import com.example.authenx.domain.model.CreateUserRequest
import com.example.authenx.domain.model.CreateUserResponse
import com.example.authenx.domain.model.User
import com.example.authenx.domain.repository.UserRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onStart
import javax.inject.Inject

class UserRepositoryImpl @Inject constructor(
    private val userDataSource: UserDataSource,
    private val authManager: AuthManager,
    private val socketManager: SocketManager
) : UserRepository {
    
    override fun getAllUsers(): Flow<List<User>> = flow {
        val token = authManager.getToken()
        if (token.isNullOrEmpty()) {
            emit(emptyList())
            return@flow
        }
    
        try {
            val response = userDataSource.getAllUsers(token)
            android.util.Log.d("UserRepository", "📥 Response code: ${response.code}, users count: ${response.users.size}")
            if (response.code == 200) {
                response.users.forEach { user ->
                    android.util.Log.d("UserRepository", "👤 User: ${user.fullName}, fingerprints: ${user.fingerprints.size}, rfidCards: ${user.rfidCards.size}")
                }
                emit(response.users)
            }
        } catch (e: Exception) {
            android.util.Log.e("UserRepository", "❌ Error loading users: ${e.message}", e)
            // Ignore initial error
        }
        
        socketManager.onUserChanged().collect {
            try {
                val response = userDataSource.getAllUsers(token)
                if (response.code == 200) {
                    emit(response.users)
                }
            } catch (e: Exception) {
                // Keep existing data
            }
        }
    }.onStart {
        android.util.Log.d("UserRepository", "🚀 Flow started - Socket should already be connected by SocketService")
        android.util.Log.d("UserRepository", "   Socket connected: ${socketManager.isConnected()}")
    }
    
    override suspend fun getUserInfo(): User? {
        return try {
            val token = authManager.getToken() ?: return null
            val response = userDataSource.getUserInfo(token)
            if (response.code == 200) response.user else null
        } catch (e: Exception) {
            null
        }
    }
    
    override suspend fun deleteUser(userId: String): Boolean {
        return try {
            val token = authManager.getToken() ?: return false
            val response = userDataSource.deleteUser(token, userId)
            response.success
        } catch (e: Exception) {
            false
        }
    }
    
    override suspend fun updateUser(user: User): Boolean {
        return try {
            val token = authManager.getToken() ?: return false
            true
        } catch (e: Exception) {
            false
        }
    }
    
    override suspend fun updateProfile(updates: Map<String, Any>): Boolean {
        return try {
            val token = authManager.getToken() ?: return false
            val response = userDataSource.updateProfile(token, updates)
            response.code == 200
        } catch (e: Exception) {
            android.util.Log.e("UserRepository", "❌ Error updating profile: ${e.message}", e)
            false
        }
    }
    
    override suspend fun createUser(request: CreateUserRequest): CreateUserResponse {
        val token = authManager.getToken() ?: throw Exception("No token found")
        return userDataSource.createUser(token, request)
    }
}
