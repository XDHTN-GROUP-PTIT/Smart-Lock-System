package com.example.authenx.domain.usecase.statistics

import com.example.authenx.domain.model.AdminStatsResponse
import com.example.authenx.domain.repository.StatisticsRepository
import javax.inject.Inject

class GetAdminStatsUseCase @Inject constructor(
    private val repository: StatisticsRepository
) {
    suspend operator fun invoke(days: Int = 7): Result<AdminStatsResponse> {
        return try {
            val response = repository.getAdminStats(days)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
