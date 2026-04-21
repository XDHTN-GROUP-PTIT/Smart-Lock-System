package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.OrganizationsResponse
import com.example.authenx.domain.repository.OrganizationRepository
import javax.inject.Inject

class GetAllOrganizationsUseCase @Inject constructor(
    private val organizationRepository: OrganizationRepository
) {
    suspend operator fun invoke(): OrganizationsResponse = organizationRepository.getAllOrganizations()
}
