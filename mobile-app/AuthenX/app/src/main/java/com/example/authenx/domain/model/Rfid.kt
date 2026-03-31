package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName
import kotlinx.serialization.Serializable

@Serializable
data class EnrollRfidRequest(
    @SerializedName("userId")
    val userId: String,
    @SerializedName("device_id")
    val deviceId: String
)

@Serializable
data class EnrollRfidResponse(
    val success: Boolean,
    val message: String,
    @SerializedName("userId")
    val userId: String? = null,
    @SerializedName("device_id")
    val deviceId: String? = null,
    val instruction: String? = null
)

@Serializable
data class DeleteRfidRequest(
    val uid: String,
    val userId: String
)

@Serializable
data class DeleteRfidResponse(
    val success: Boolean,
    val message: String
)
