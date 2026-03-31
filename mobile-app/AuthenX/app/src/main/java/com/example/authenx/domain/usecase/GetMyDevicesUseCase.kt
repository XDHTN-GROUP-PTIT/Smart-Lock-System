package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.DevicesResponse
import com.example.authenx.domain.repository.DeviceRepository
import javax.inject.Inject

class GetMyDevicesUseCase @Inject constructor(
    private val deviceRepository: DeviceRepository
) {
    suspend operator fun invoke(): Result<DevicesResponse> {
        return try {
            val response = deviceRepository.getMyDevices()
            if (response.success) {
                Result.success(response)
            } else {
                Result.failure(Exception(response.message ?: "Failed to get devices"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
