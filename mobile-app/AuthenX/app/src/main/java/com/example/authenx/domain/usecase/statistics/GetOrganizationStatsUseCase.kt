package com.example.authenx.domain.usecase.statistics

import com.example.authenx.domain.model.OrganizationStatsResponse
import com.example.authenx.domain.repository.StatisticsRepository
import javax.inject.Inject

class GetOrganizationStatsUseCase @Inject constructor(
    private val repository: StatisticsRepository
) {
    suspend operator fun invoke(orgId: String): OrganizationStatsResponse = repository.getOrganizationStats(orgId)
}
