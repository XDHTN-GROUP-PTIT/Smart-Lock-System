package com.example.authenx.domain.usecase

import com.example.authenx.domain.repository.UserRepository
import javax.inject.Inject

class DeleteUserUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(userId: String): Boolean = 
        userRepository.deleteUser(userId)
}
