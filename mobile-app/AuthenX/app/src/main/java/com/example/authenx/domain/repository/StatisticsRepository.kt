package com.example.authenx.domain.repository

import com.example.authenx.domain.model.AccessStatistics
import com.example.authenx.domain.model.AdminStatsResponse
import com.example.authenx.domain.model.Organization
import com.example.authenx.domain.model.OrganizationListResponse
import com.example.authenx.domain.model.OrganizationStatsResponse
import com.example.authenx.domain.model.UserManagerStatsResponse
import kotlinx.coroutines.flow.Flow

interface StatisticsRepository {
    fun getStatistics(
        startDate: String? = null,
        endDate: String? = null,
        userId: String? = null
    ): Flow<AccessStatistics?>
    
    suspend fun getUserManagerStats(days: Int = 7): UserManagerStatsResponse
    suspend fun getAdminStats(days: Int = 7): AdminStatsResponse
    suspend fun getOrganizations(): OrganizationListResponse
    suspend fun getOrganizationStats(orgId: String): OrganizationStatsResponse
}
