package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.AccessStatistics
import com.example.authenx.domain.repository.StatisticsRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetStatisticsUseCase @Inject constructor(
    private val statisticsRepository: StatisticsRepository
) {
    operator fun invoke(
        startDate: String? = null,
        endDate: String? = null,
        userId: String? = null
    ): Flow<AccessStatistics?> {
        return statisticsRepository.getStatistics(startDate, endDate, userId)
    }
}
