package com.example.authenx.domain.repository

import com.example.authenx.domain.model.CheckActionResponse
import com.example.authenx.domain.model.DeleteFaceResponse
import com.example.authenx.domain.model.RegisterFaceResponse
import com.example.authenx.domain.model.UnlockByFaceResponse
import com.example.authenx.domain.model.VerifyFaceResponse

interface FaceRecognitionRepository {
    suspend fun verifyFace(imageBase64: String): Result<VerifyFaceResponse>
    suspend fun checkAction(imageBase64: String, initialX: Double, direction: String): Result<CheckActionResponse>
    suspend fun registerFace(imageBase64: String, userId: String): Result<RegisterFaceResponse>
    suspend fun deleteFace(userId: String): Result<DeleteFaceResponse>
    suspend fun unlockByFace(deviceId: String, token: String): Result<UnlockByFaceResponse>
}
