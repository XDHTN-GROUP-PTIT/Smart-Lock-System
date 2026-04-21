package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.User
import com.example.authenx.domain.repository.UserRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetAllUsersUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    operator fun invoke(): Flow<List<User>> = userRepository.getAllUsers()
}
