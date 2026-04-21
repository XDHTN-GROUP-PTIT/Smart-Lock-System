package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.CreateOrganizationRequest
import com.example.authenx.domain.model.CreateOrganizationResponse
import com.example.authenx.domain.repository.OrganizationRepository
import javax.inject.Inject

class CreateOrganizationUseCase @Inject constructor(
    private val organizationRepository: OrganizationRepository
) {
    suspend operator fun invoke(name: String, address: String?): Result<CreateOrganizationResponse> {
        return try {
            if (name.isBlank()) {
                return Result.failure(Exception("Organization name is required"))
            }

            val request = CreateOrganizationRequest(name, address)
            val response = organizationRepository.createOrganization(request)

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
