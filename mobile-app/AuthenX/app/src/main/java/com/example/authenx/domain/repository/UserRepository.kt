package com.example.authenx.domain.repository

import com.example.authenx.domain.model.CreateUserRequest
import com.example.authenx.domain.model.CreateUserResponse
import com.example.authenx.domain.model.User
import kotlinx.coroutines.flow.Flow

interface UserRepository {
    fun getAllUsers(): Flow<List<User>>
    suspend fun getUserInfo(): User?
    suspend fun deleteUser(userId: String): Boolean
    suspend fun updateUser(user: User): Boolean
    suspend fun updateProfile(updates: Map<String, Any>): Boolean
    suspend fun createUser(request: CreateUserRequest): CreateUserResponse
}
