package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName
import java.util.*

data class User(
    @SerializedName(value = "id", alternate = ["_id"])
    val id: String = "",
    val email: String = "",
    val fullName: String = "",
    val phone: String = "",
    val role: String = "",
    @SerializedName("org_id")
    val orgId: String? = null,
    @SerializedName("created_at")
    val createdAt: Date = Date(),
    val fingerprints: List<FingerprintInfo> = emptyList(),
    val rfidCards: List<RfidCardInfo> = emptyList()
)

data class FingerprintInfo(
    val id: String,
    val fingerprintId: String,
    val deviceId: String?,
    val createdAt: Date
)

data class RfidCardInfo(
    val id: String,
    val cardUid: String,
    val deviceId: String?,
    val createdAt: Date
)

data class UserInfoResponse(
    val code: Int,
    val message: String,
    val user: User
)
