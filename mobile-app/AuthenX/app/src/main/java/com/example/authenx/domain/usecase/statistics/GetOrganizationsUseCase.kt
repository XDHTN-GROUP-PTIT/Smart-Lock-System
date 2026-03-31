package com.example.authenx.domain.usecase.statistics

import com.example.authenx.domain.model.OrganizationListResponse
import com.example.authenx.domain.repository.StatisticsRepository
import javax.inject.Inject

class GetOrganizationsUseCase @Inject constructor(
    private val repository: StatisticsRepository
) {
    suspend operator fun invoke(): OrganizationListResponse = repository.getOrganizations()
}
