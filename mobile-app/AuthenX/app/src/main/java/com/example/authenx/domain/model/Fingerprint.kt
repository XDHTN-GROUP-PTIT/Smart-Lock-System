package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

data class Fingerprint(
    @SerializedName("_id")
    val id: String,
    @SerializedName("fingerprint_id")
    val fingerprintId: String,
    @SerializedName("user_id")
    val userId: String,
    @SerializedName("template_base64")
    val templateBase64: String,
    @SerializedName("finger_position")
    val fingerPosition: String, // "thumb", "index", "middle", "ring", "pinky", "unknown"
    val hand: String, // "left", "right", "unknown"
    @SerializedName("registered_at")
    val registeredAt: String
)

data class FingerprintsResponse(
    val success: Boolean,
    val message: String?,
    val data: List<Fingerprint>
)

data class AddFingerprintRequest(
    @SerializedName("user_id")
    val userId: String,
    @SerializedName("template_base64")
    val templateBase64: String,
    @SerializedName("finger_position")
    val fingerPosition: String = "unknown",
    val hand: String = "unknown"
)
