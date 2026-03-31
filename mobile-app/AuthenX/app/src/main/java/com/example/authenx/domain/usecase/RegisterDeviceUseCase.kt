package com.example.authenx.domain.usecase

import com.example.authenx.domain.model.RegisterDeviceRequest
import com.example.authenx.domain.model.RegisterDeviceResponse
import com.example.authenx.domain.repository.DeviceRepository
import javax.inject.Inject

class RegisterDeviceUseCase @Inject constructor(
    private val deviceRepository: DeviceRepository
) {
    suspend operator fun invoke(deviceId: String, type: String, model: String): Result<RegisterDeviceResponse> {
        return try {
            if (deviceId.isBlank()) {
                return Result.failure(Exception("Device ID cannot be empty"))
            }

            if (type.isBlank()) {
                return Result.failure(Exception("Device Type cannot be empty"))
            }

            if (model.isBlank()) {
                return Result.failure(Exception("Device Model cannot be empty"))
            }

            val request = RegisterDeviceRequest(
                deviceId = deviceId,
                type = type,
                model = model
            )

            val response = deviceRepository.registerDevice(request)
            if (response.success) {
                Result.success(response)
            } else {
                Result.failure(Exception(response.message))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
