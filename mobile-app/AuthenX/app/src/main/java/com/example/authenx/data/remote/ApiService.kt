package com.example.authenx.data.remote

import com.example.authenx.BuildConfig
import com.example.authenx.domain.model.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

class ApiService(private val client: HttpClient) {
    
    companion object {
        const val BASE_URL = BuildConfig.API_BASE_URL
    }
    
    suspend fun login(request: LoginRequest): AuthResponse {
        return client.post("$BASE_URL/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun register(request: RegisterRequest): AuthResponse {
        return client.post("$BASE_URL/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
}
