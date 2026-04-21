package com.example.authenx.data.repository

import android.util.Log
import com.example.authenx.data.remote.source.DeviceDataSource
import com.example.authenx.domain.model.DevicesResponse
import com.example.authenx.domain.model.RegisterDeviceRequest
import com.example.authenx.domain.model.RegisterDeviceResponse
import com.example.authenx.domain.repository.DeviceRepository
import javax.inject.Inject

class DeviceRepositoryImpl @Inject constructor(
    private val deviceDataSource: DeviceDataSource
) : DeviceRepository {

    override suspend fun getMyDevices(): DevicesResponse {
        return deviceDataSource.getMyDevices()
    }

    override suspend fun registerDevice(request: RegisterDeviceRequest): RegisterDeviceResponse {
        return deviceDataSource.registerDevice(request)
    }

    override suspend fun deleteDevice(deviceId: String): Boolean {
        return try {
            val response = deviceDataSource.deleteDevice(deviceId)
            Log.d("DeviceRepository", "Delete device response: success=${response.success}, message=${response.message}")
            response.success
        } catch (e: Exception) {
            Log.e("DeviceRepository", "Error deleting device: ${e.message}", e)
            false
        }
    }
}
