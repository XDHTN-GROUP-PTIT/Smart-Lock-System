package com.example.authenx.data.remote.source

import com.example.authenx.BuildConfig
import com.example.authenx.domain.model.CheckActionRequest
import com.example.authenx.domain.model.CheckActionResponse
import com.example.authenx.domain.model.DeleteFaceRequest
import com.example.authenx.domain.model.DeleteFaceResponse
import com.example.authenx.domain.model.RegisterFaceRequest
import com.example.authenx.domain.model.RegisterFaceResponse
import com.example.authenx.domain.model.UnlockByFaceRequest
import com.example.authenx.domain.model.UnlockByFaceResponse
import com.example.authenx.domain.model.VerifyFaceRequest
import com.example.authenx.domain.model.VerifyFaceResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import javax.inject.Inject

class FaceRecognitionDataSource @Inject constructor(
    private val httpClient: HttpClient
) {
    private val baseUrl = BuildConfig.FACE_RECOGNITION_BASE_URL
    
    suspend fun verifyFace(imageBase64: String): VerifyFaceResponse {
        return httpClient.post("$baseUrl/verify") {
            contentType(ContentType.Application.Json)
            setBody(VerifyFaceRequest(imageBase64))
        }.body()
    }
    
    suspend fun checkAction(
        imageBase64: String,
        initialX: Double,
        direction: String
    ): CheckActionResponse {
        return httpClient.post("$baseUrl/check-action") {
            contentType(ContentType.Application.Json)
            setBody(CheckActionRequest(imageBase64, initialX, direction))
        }.body()
    }
    
    suspend fun registerFace(imageBase64: String, userId: String): RegisterFaceResponse {
        return httpClient.post("$baseUrl/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterFaceRequest(imageBase64, userId))
        }.body()
    }
    
    suspend fun deleteFace(userId: String): DeleteFaceResponse {
        return httpClient.post("$baseUrl/delete-face") {
            contentType(ContentType.Application.Json)
            setBody(DeleteFaceRequest(userId))
        }.body()
    }
    
    suspend fun unlockByFace(deviceId: String, token: String): UnlockByFaceResponse {
        return httpClient.post("${BuildConfig.API_BASE_URL}/face/unlock") {
            contentType(ContentType.Application.Json)
            bearerAuth(token)
            setBody(UnlockByFaceRequest(deviceId))
        }.body()
    }
}
