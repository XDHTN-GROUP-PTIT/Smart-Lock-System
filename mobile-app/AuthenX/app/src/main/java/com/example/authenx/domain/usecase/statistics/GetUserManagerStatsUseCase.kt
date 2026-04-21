package com.example.authenx.domain.usecase.statistics

import com.example.authenx.domain.model.UserManagerStatsResponse
import com.example.authenx.domain.repository.StatisticsRepository
import javax.inject.Inject

class GetUserManagerStatsUseCase @Inject constructor(
    private val repository: StatisticsRepository
) {
    suspend operator fun invoke(days: Int = 7): Result<UserManagerStatsResponse> {
        return try {
            val response = repository.getUserManagerStats(days)
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
