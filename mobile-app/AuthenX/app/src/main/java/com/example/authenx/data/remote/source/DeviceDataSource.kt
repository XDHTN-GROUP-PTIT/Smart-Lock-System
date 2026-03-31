package com.example.authenx.data.remote.source

import com.example.authenx.BuildConfig
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.DeleteDeviceResponse
import com.example.authenx.domain.model.DevicesResponse
import com.example.authenx.domain.model.RegisterDeviceRequest
import com.example.authenx.domain.model.RegisterDeviceResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import javax.inject.Inject

class DeviceDataSource @Inject constructor(
    private val httpClient: HttpClient,
    private val authManager: AuthManager
) {
    private val baseUrl = BuildConfig.API_BASE_URL

    suspend fun getMyDevices(): DevicesResponse {
        val token = authManager.getToken()
        return httpClient.get("$baseUrl/device/my-devices") {
            header("Authorization", "Bearer $token")
        }.body()
    }

    suspend fun registerDevice(request: RegisterDeviceRequest): RegisterDeviceResponse {
        val token = authManager.getToken()
        return httpClient.post("$baseUrl/device/register") {
            header("Authorization", "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }

    suspend fun deleteDevice(deviceId: String): DeleteDeviceResponse {
        val token = authManager.getToken()
        return httpClient.delete("$baseUrl/device/$deviceId") {
            header("Authorization", "Bearer $token")
        }.body()
    }
}
