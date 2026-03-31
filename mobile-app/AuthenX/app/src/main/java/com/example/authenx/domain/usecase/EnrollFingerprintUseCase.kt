package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.EnrollFingerprintRequest
import com.example.authenx.domain.model.EnrollFingerprintResponse
import com.example.authenx.domain.repository.BiometricRepository
import javax.inject.Inject

class EnrollFingerprintUseCase @Inject constructor(
    private val biometricRepository: BiometricRepository
) {
    suspend operator fun invoke(userId: String, deviceId: String): Result<EnrollFingerprintResponse> {
        return try {
            val request = EnrollFingerprintRequest(userId, deviceId)
            val response = biometricRepository.enrollFingerprint(request)
            
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
