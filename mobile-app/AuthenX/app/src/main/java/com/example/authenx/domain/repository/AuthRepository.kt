package com.example.authenx.domain.repository

import com.example.authenx.domain.model.AuthResponse
import com.example.authenx.domain.model.LoginRequest
import com.example.authenx.domain.model.RegisterRequest

interface AuthRepository {
    suspend fun login(request: LoginRequest): AuthResponse
    suspend fun register(request: RegisterRequest): AuthResponse
}