package com.example.authenx.domain.usecase

import com.example.authenx.domain.repository.UserRepository
import javax.inject.Inject

class UpdateProfileUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(updates: Map<String, Any>): Boolean = userRepository.updateProfile(updates)
}
