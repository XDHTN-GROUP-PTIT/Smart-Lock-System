package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.RegisterRequest
import com.example.authenx.domain.repository.AuthRepository
import javax.inject.Inject

class RegisterUseCase @Inject constructor (private val authRepository: AuthRepository) {
    suspend operator fun invoke(request: RegisterRequest) = authRepository.register(request)
}
