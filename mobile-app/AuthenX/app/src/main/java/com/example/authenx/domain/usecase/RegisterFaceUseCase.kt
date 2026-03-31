package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.RegisterFaceResponse
import com.example.authenx.domain.repository.FaceRecognitionRepository
import javax.inject.Inject

class RegisterFaceUseCase @Inject constructor(
    private val repository: FaceRecognitionRepository
) {
    suspend operator fun invoke(imageBase64: String, userId: String): Result<RegisterFaceResponse> {
        return repository.registerFace(imageBase64, userId)
    }
}
