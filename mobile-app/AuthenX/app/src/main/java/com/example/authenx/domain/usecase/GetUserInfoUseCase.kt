package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.User
import com.example.authenx.domain.repository.UserRepository
import javax.inject.Inject

class GetUserInfoUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(): User? = userRepository.getUserInfo()
}
