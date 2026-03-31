package com.example.authenx.data.remote.source

import com.example.authenx.BuildConfig
import com.example.authenx.data.remote.ApiService
import com.example.authenx.domain.model.ApiResponse
import com.example.authenx.domain.model.CreateUserRequest
import com.example.authenx.domain.model.CreateUserResponse
import com.example.authenx.domain.model.User
import com.example.authenx.domain.model.UserInfoResponse
import com.example.authenx.domain.model.UsersResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import javax.inject.Inject

class UserDataSource @Inject constructor (private val httpClient: HttpClient) {

    suspend fun getAllUsers(token: String): UsersResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/user/children") {
            bearerAuth(token)
        }.body()
    }

    suspend fun getUserInfo(token: String): UserInfoResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/user/info") {
            bearerAuth(token)
        }.body()
    }

    suspend fun deleteUser(token: String, userId: String): ApiResponse<Unit> {
        return httpClient.delete("${ApiService.Companion.BASE_URL}/user/delete/$userId") {
            bearerAuth(token)
        }.body()
    }
    
    suspend fun createUser(token: String, request: CreateUserRequest): CreateUserResponse {
        return httpClient.post("${BuildConfig.API_BASE_URL}/user/create") {
            bearerAuth(token)
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun updateProfile(token: String, updates: Map<String, Any>): UserInfoResponse {
        return httpClient.patch("${BuildConfig.API_BASE_URL}/user/update") {
            bearerAuth(token)
            contentType(ContentType.Application.Json)
            setBody(updates)
        }.body()
    }
}