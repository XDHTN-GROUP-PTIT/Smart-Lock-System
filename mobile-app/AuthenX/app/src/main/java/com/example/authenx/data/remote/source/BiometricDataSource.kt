package com.example.authenx.data.remote.source

import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.DeleteFingerprintRequest
import com.example.authenx.domain.model.DeleteFingerprintResponse
import com.example.authenx.domain.model.EnrollFingerprintRequest
import com.example.authenx.domain.model.EnrollFingerprintResponse
import com.example.authenx.domain.model.EnrollRfidRequest
import com.example.authenx.domain.model.EnrollRfidResponse
import com.example.authenx.domain.model.DeleteRfidRequest
import com.example.authenx.domain.model.DeleteRfidResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.delete
import io.ktor.client.request.headers
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import javax.inject.Inject

class BiometricDataSource @Inject constructor(
    private val client: HttpClient,
    private val authManager: AuthManager
) {
    private val baseUrl = com.example.authenx.BuildConfig.API_BASE_URL
    
    suspend fun enrollFingerprint(request: EnrollFingerprintRequest): EnrollFingerprintResponse {
        val token = authManager.getToken()
        
        return client.post("$baseUrl/fingerprint/enroll") {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
            }
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun deleteFingerprint(request: DeleteFingerprintRequest): DeleteFingerprintResponse {
        val token = authManager.getToken()
        
        return client.delete("$baseUrl/fingerprint/delete") {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
            }
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun enrollRfid(request: EnrollRfidRequest): EnrollRfidResponse {
        val token = authManager.getToken()
        
        return client.post("$baseUrl/rfid/enroll") {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
            }
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
    
    suspend fun deleteRfid(request: DeleteRfidRequest): DeleteRfidResponse {
        val token = authManager.getToken()
        
        return client.delete("$baseUrl/rfid/delete") {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
            }
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }
}
