package com.example.authenx.domain.repository

import com.example.authenx.domain.model.CreateOrganizationRequest
import com.example.authenx.domain.model.CreateOrganizationResponse
import com.example.authenx.domain.model.OrganizationsResponse

interface OrganizationRepository {
    suspend fun createOrganization(request: CreateOrganizationRequest): CreateOrganizationResponse
    suspend fun getAllOrganizations(): OrganizationsResponse
    suspend fun deleteOrganization(id: String): CreateOrganizationResponse
}
