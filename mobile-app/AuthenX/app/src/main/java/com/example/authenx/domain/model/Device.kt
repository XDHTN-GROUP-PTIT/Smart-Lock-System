package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

data class Device(
    @SerializedName("_id")
    val id: String,
    @SerializedName("device_id")
    val deviceId: String,
    val type: String?,
    val model: String?,
    val status: String, // "pending", "registered", "online", "offline", "blocked"
    @SerializedName("fw_current")
    val fwCurrent: String?,
    @SerializedName("org_id")
    val orgId: String?,
    @SerializedName("last_seen")
    val lastSeen: String?,
    val createdAt: String?,
    val updatedAt: String?
)

data class DevicesResponse(
    val success: Boolean,
    val message: String?,
    val count: Int = 0,
    val data: List<Device>
)

data class RegisterDeviceRequest(
    @SerializedName("device_id")
    val deviceId: String,
    val type: String,
    val model: String
)

data class RegisterDeviceResponse(
    val success: Boolean,
    val message: String,
    @SerializedName("device_id")
    val deviceId: String? = null,
    val status: String? = null,
    @SerializedName("token_expires")
    val tokenExpires: String? = null
)

data class DeleteDeviceResponse(
    val success: Boolean,
    val message: String
)
