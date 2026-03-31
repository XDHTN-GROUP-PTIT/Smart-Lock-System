package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.DeleteRfidRequest
import com.example.authenx.domain.model.DeleteRfidResponse
import com.example.authenx.domain.repository.BiometricRepository
import javax.inject.Inject

class DeleteRfidUseCase @Inject constructor(
    private val biometricRepository: BiometricRepository
) {
    suspend operator fun invoke(request: DeleteRfidRequest): DeleteRfidResponse {
        return biometricRepository.deleteRfid(request)
    }
}
