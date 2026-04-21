package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.DeleteFingerprintRequest
import com.example.authenx.domain.model.DeleteFingerprintResponse
import com.example.authenx.domain.repository.BiometricRepository
import javax.inject.Inject

class DeleteFingerprintUseCase @Inject constructor(
    private val biometricRepository: BiometricRepository
) {
    suspend operator fun invoke(request: DeleteFingerprintRequest): DeleteFingerprintResponse {
        return biometricRepository.deleteFingerprint(request)
    }
}
