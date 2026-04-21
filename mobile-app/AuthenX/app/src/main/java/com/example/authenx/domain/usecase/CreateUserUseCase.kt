package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.CreateUserRequest
import com.example.authenx.domain.model.CreateUserResponse
import com.example.authenx.domain.repository.UserRepository
import javax.inject.Inject

class CreateUserUseCase @Inject constructor(
    private val userRepository: UserRepository
) {
    suspend operator fun invoke(fullName: String, phone: String): Result<CreateUserResponse> {
        return try {
            if (fullName.isBlank()) {
                return Result.failure(Exception("Name is required"))
            }
            
            if (phone.isBlank()) {
                return Result.failure(Exception("Phone is required"))
            }
            
            // Validate phone format (basic)
            if (!phone.matches(Regex("^[0-9]{10,11}$"))) {
                return Result.failure(Exception("Invalid phone number"))
            }
            
            val request = CreateUserRequest(fullName, phone)
            val response = userRepository.createUser(request)
            
            if (response.code == 200) {
                Result.success(response)
            } else {
                Result.failure(Exception(response.message))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
