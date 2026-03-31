package com.example.authenx.data.repository

import com.example.authenx.data.remote.source.AuthDataSource
import com.example.authenx.domain.model.AuthResponse
import com.example.authenx.domain.model.LoginRequest
import com.example.authenx.domain.model.RegisterRequest
import com.example.authenx.domain.repository.AuthRepository

class AuthRepositoryImpl (private val authDataSource: AuthDataSource): AuthRepository {
    override suspend fun login(request: LoginRequest): AuthResponse {
        return authDataSource.login(request)
    }
    
    override suspend fun register(request: RegisterRequest): AuthResponse {
        return authDataSource.register(request)
    }
}