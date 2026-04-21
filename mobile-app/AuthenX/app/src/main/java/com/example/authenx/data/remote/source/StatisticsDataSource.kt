package com.example.authenx.data.remote.source

import com.example.authenx.data.remote.ApiService
import com.example.authenx.domain.model.StatisticsResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import javax.inject.Inject

class StatisticsDataSource @Inject constructor(
    private val httpClient: HttpClient
) {
    suspend fun getStatistics(
        token: String,
        startDate: String? = null,
        endDate: String? = null,
        userId: String? = null
    ): StatisticsResponse {
        // This endpoint is deprecated, use getUserManagerStats or getAdminStats instead
        return httpClient.get("${ApiService.Companion.BASE_URL}/stats") {
            bearerAuth(token)
            parameter("days", 7)
        }.body()
    }

    suspend fun getUserManagerStats(
        token: String,
        days: Int = 7
    ): com.example.authenx.domain.model.UserManagerStatsResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/stats") {
            bearerAuth(token)
            parameter("days", days)
        }.body()
    }

    suspend fun getAdminStats(
        token: String,
        days: Int = 7
    ): com.example.authenx.domain.model.AdminStatsResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/stats/admin") {
            bearerAuth(token)
            parameter("days", days)
        }.body()
    }

    suspend fun getOrganizations(
        token: String
    ): com.example.authenx.domain.model.OrganizationListResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/organization") {
            bearerAuth(token)
        }.body()
    }

    suspend fun getOrganizationStats(
        token: String,
        orgId: String
    ): com.example.authenx.domain.model.OrganizationStatsResponse {
        return httpClient.get("${ApiService.Companion.BASE_URL}/stats/organization/${orgId}") {
            bearerAuth(token)
        }.body()
    }
}
