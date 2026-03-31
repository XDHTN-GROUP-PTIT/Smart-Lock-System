package com.example.authenx.data.repository

import com.example.authenx.data.remote.source.OrganizationDataSource
import com.example.authenx.domain.model.CreateOrganizationRequest
import com.example.authenx.domain.model.CreateOrganizationResponse
import com.example.authenx.domain.model.OrganizationsResponse
import com.example.authenx.domain.repository.OrganizationRepository
import javax.inject.Inject

class OrganizationRepositoryImpl @Inject constructor(
    private val organizationDataSource: OrganizationDataSource
) : OrganizationRepository {

    override suspend fun createOrganization(request: CreateOrganizationRequest): CreateOrganizationResponse {
        return organizationDataSource.createOrganization(request)
    }

    override suspend fun getAllOrganizations(): OrganizationsResponse {
        return organizationDataSource.getAllOrganizations()
    }

    override suspend fun deleteOrganization(id: String): CreateOrganizationResponse {
        return organizationDataSource.deleteOrganization(id)
    }
}
