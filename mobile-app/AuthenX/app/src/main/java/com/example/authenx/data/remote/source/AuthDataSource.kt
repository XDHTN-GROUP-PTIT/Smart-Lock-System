package com.example.authenx.data.remote.source

import com.example.authenx.BuildConfig
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.AuthResponse
import com.example.authenx.domain.model.LoginRequest
import com.example.authenx.domain.model.RegisterRequest
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import javax.inject.Inject

class AuthDataSource @Inject constructor(
    private val httpClient: HttpClient,
    private val authManager: AuthManager
) {

    companion object {
        const val BASE_URL = BuildConfig.API_BASE_URL
    }

    suspend fun login(request: LoginRequest): AuthResponse {
        return httpClient.post ("$BASE_URL/user/login") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun register(request: RegisterRequest): AuthResponse {
        val token = authManager.getToken()
            ?: throw Exception("No authentication token found. Admin must be logged in to create user_manager.")
        
        return httpClient.post ("$BASE_URL/user/register") {
            bearerAuth(token)
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
}