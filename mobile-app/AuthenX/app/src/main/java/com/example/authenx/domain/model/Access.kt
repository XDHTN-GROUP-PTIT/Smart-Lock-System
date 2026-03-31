package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

data class AuthenticateRFIDRequest(
    val uid: String,
    @SerializedName("device_id")
    val deviceId: String
)

data class AuthenticateFingerprintRequest(
    @SerializedName("template_base64")
    val templateBase64: String,
    @SerializedName("device_id")
    val deviceId: String
)

data class RemoteUnlockRequest(
    @SerializedName("device_id")
    val deviceId: String,
    @SerializedName("user_id")
    val userId: String
)

data class AccessResponse(
    val success: Boolean,
    val message: String,
    val data: AccessData?
)

data class AccessData(
    @SerializedName("access_granted")
    val accessGranted: Boolean,
    @SerializedName("user_id")
    val userId: String?,
    @SerializedName("user_name")
    val userName: String?,
    @SerializedName("access_method")
    val accessMethod: String,
    val timestamp: String
)

data class DoorStatus(
    @SerializedName("device_id")
    val deviceId: String,
    @SerializedName("is_locked")
    val isLocked: Boolean,
    @SerializedName("last_access")
    val lastAccess: String?
)

data class DoorStatusResponse(
    val success: Boolean,
    val message: String?,
    val data: DoorStatus
)
