package com.example.authenx.domain.usecase

import com.example.authenx.domain.repository.DeviceRepository
import javax.inject.Inject

class DeleteDeviceUseCase @Inject constructor(
    private val deviceRepository: DeviceRepository
) {
    suspend operator fun invoke(deviceId: String): Boolean {
        return deviceRepository.deleteDevice(deviceId)
    }
}
