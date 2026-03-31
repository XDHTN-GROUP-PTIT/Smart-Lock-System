package com.example.authenx.domain.repository

import com.example.authenx.domain.model.DeleteDeviceResponse
import com.example.authenx.domain.model.DevicesResponse
import com.example.authenx.domain.model.RegisterDeviceRequest
import com.example.authenx.domain.model.RegisterDeviceResponse

interface DeviceRepository {
    suspend fun getMyDevices(): DevicesResponse
    suspend fun registerDevice(request: RegisterDeviceRequest): RegisterDeviceResponse
    suspend fun deleteDevice(deviceId: String): Boolean
}
