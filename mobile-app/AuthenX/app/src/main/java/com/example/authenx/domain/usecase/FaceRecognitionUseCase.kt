package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.CheckActionResponse
import com.example.authenx.domain.model.VerifyFaceResponse
import com.example.authenx.domain.repository.FaceRecognitionRepository
import javax.inject.Inject

class VerifyFaceUseCase @Inject constructor(
    private val repository: FaceRecognitionRepository
) {
    suspend operator fun invoke(imageBase64: String): Result<VerifyFaceResponse> {
        return repository.verifyFace(imageBase64)
    }
}

class CheckActionUseCase @Inject constructor(
    private val repository: FaceRecognitionRepository
) {
    suspend operator fun invoke(
        imageBase64: String,
        initialX: Double,
        direction: String
    ): Result<CheckActionResponse> {
        return repository.checkAction(imageBase64, initialX, direction)
    }
}
