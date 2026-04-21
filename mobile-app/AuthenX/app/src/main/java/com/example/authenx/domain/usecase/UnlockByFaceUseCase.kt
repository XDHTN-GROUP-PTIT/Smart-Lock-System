package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.UnlockByFaceResponse
import com.example.authenx.domain.repository.FaceRecognitionRepository
import javax.inject.Inject

class UnlockByFaceUseCase @Inject constructor(
    private val repository: FaceRecognitionRepository
) {
    suspend operator fun invoke(deviceId: String, token: String): Result<UnlockByFaceResponse> {
        return repository.unlockByFace(deviceId, token)
    }
}
