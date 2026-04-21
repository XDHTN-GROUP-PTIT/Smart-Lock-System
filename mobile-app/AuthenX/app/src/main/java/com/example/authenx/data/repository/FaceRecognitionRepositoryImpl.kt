package com.example.authenx.data.repository

import com.example.authenx.data.remote.source.FaceRecognitionDataSource
import com.example.authenx.domain.model.CheckActionResponse
import com.example.authenx.domain.model.DeleteFaceResponse
import com.example.authenx.domain.model.RegisterFaceResponse
import com.example.authenx.domain.model.UnlockByFaceResponse
import com.example.authenx.domain.model.VerifyFaceResponse
import com.example.authenx.domain.repository.FaceRecognitionRepository
import javax.inject.Inject

class FaceRecognitionRepositoryImpl @Inject constructor(
    private val dataSource: FaceRecognitionDataSource
) : FaceRecognitionRepository {
    
    override suspend fun verifyFace(imageBase64: String): Result<VerifyFaceResponse> {
        return try {
            val response = dataSource.verifyFace(imageBase64)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override suspend fun checkAction(
        imageBase64: String,
        initialX: Double,
        direction: String
    ): Result<CheckActionResponse> {
        return try {
            val response = dataSource.checkAction(imageBase64, initialX, direction)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override suspend fun registerFace(imageBase64: String, userId: String): Result<RegisterFaceResponse> {
        return try {
            val response = dataSource.registerFace(imageBase64, userId)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override suspend fun deleteFace(userId: String): Result<DeleteFaceResponse> {
        return try {
            val response = dataSource.deleteFace(userId)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override suspend fun unlockByFace(deviceId: String, token: String): Result<UnlockByFaceResponse> {
        return try {
            val response = dataSource.unlockByFace(deviceId, token)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
