package com.example.authenx.data.repository

import com.example.authenx.data.local.AuthManager
import com.example.authenx.data.remote.socket.SocketManager
import com.example.authenx.data.remote.source.StatisticsDataSource
import com.example.authenx.domain.model.AccessStatistics
import com.example.authenx.domain.repository.StatisticsRepository
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onStart
import javax.inject.Inject

class StatisticsRepositoryImpl @Inject constructor(
    private val statisticsDataSource: StatisticsDataSource,
    private val authManager: AuthManager,
    private val socketManager: SocketManager
) : StatisticsRepository {
    
    override fun getStatistics(
        startDate: String?,
        endDate: String?,
        userId: String?
    ): Flow<AccessStatistics?> = flow {
        val token = authManager.getToken()
        if (token.isNullOrEmpty()) {
            emit(null)
            return@flow
        }
        
        // Initial fetch
        try {
            val response = statisticsDataSource.getStatistics(token, startDate, endDate, userId)
            if (response.success) {
                emit(response.data)
            }
        } catch (e: Exception) {
            // Ignore initial error
        }
        
        // Listen to real-time updates
        socketManager.onAccessLogCreated().collect { event ->
            // Fetch updated statistics when new log is created
            try {
                val response = statisticsDataSource.getStatistics(token, startDate, endDate, userId)
                if (response.success) {
                    emit(response.data)
                }
            } catch (e: Exception) {
                // Keep existing data
            }
        }
    }.onStart {
        // Connect socket when flow starts
        val token = authManager.getToken()
        if (!token.isNullOrEmpty()) {
            val baseUrl = com.example.authenx.BuildConfig.API_BASE_URL.replace("/api", "")
            val userId = authManager.getUserId()
            socketManager.connect(baseUrl, token, userId)
        }
    }

    override suspend fun getUserManagerStats(days: Int): com.example.authenx.domain.model.UserManagerStatsResponse {
        val token = authManager.getToken() ?: throw Exception("Token not found")
        return statisticsDataSource.getUserManagerStats(token, days)
    }

    override suspend fun getAdminStats(days: Int): com.example.authenx.domain.model.AdminStatsResponse {
        val token = authManager.getToken() ?: throw Exception("Token not found")
        return statisticsDataSource.getAdminStats(token, days)
    }

    override suspend fun getOrganizations(): com.example.authenx.domain.model.OrganizationListResponse {
        val token = authManager.getToken() ?: throw Exception("Token not found")
        return statisticsDataSource.getOrganizations(token)
    }

    override suspend fun getOrganizationStats(orgId: String): com.example.authenx.domain.model.OrganizationStatsResponse {
        val token = authManager.getToken() ?: throw Exception("Token not found")
        return statisticsDataSource.getOrganizationStats(token, orgId)
    }
}
