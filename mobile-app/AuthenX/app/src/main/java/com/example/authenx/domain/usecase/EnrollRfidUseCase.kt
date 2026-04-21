package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.EnrollRfidRequest
import com.example.authenx.domain.model.EnrollRfidResponse
import com.example.authenx.domain.repository.BiometricRepository
import javax.inject.Inject

class EnrollRfidUseCase @Inject constructor(
    private val biometricRepository: BiometricRepository
) {
    suspend operator fun invoke(userId: String, deviceId: String): Result<EnrollRfidResponse> {
        return try {
            val request = EnrollRfidRequest(userId, deviceId)
            val response = biometricRepository.enrollRfid(request)
            
            if (response.success) {
                Result.success(response)
            } else {
                Result.failure(Exception(response.message))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
