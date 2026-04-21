package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.DeleteFaceResponse
import com.example.authenx.domain.repository.FaceRecognitionRepository
import javax.inject.Inject

class DeleteFaceUseCase @Inject constructor(
    private val repository: FaceRecognitionRepository
) {
    suspend operator fun invoke(userId: String): Result<DeleteFaceResponse> {
        return repository.deleteFace(userId)
    }
}
