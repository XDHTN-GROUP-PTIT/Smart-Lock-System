package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.LoginRequest
import com.example.authenx.domain.repository.AuthRepository
import javax.inject.Inject

class LoginUseCase @Inject constructor (private val authRepository: AuthRepository) {
    suspend operator fun invoke(request: LoginRequest) = authRepository.login(request)
}