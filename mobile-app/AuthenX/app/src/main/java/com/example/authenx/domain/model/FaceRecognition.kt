package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

data class VerifyFaceResponse(
    val verified: Boolean,
    val person: String,
    val similarity: Double,
    @SerializedName("initial_x")
    val initialX: Double
)

data class CheckActionResponse(
    val moved: Boolean,
    val delta: Double
)

data class VerifyFaceRequest(
    @SerializedName("image_base64")
    val imageBase64: String
)

data class CheckActionRequest(
    @SerializedName("image_base64")
    val imageBase64: String,
    @SerializedName("initial_x")
    val initialX: Double,
    val direction: String // "left" or "right"
)

enum class FaceRecognitionState {
    IDLE,
    CAPTURING_FRONT,
    VERIFYING,
    WAITING_ACTION,
    CAPTURING_ACTION,
    CHECKING_ACTION,
    SUCCESS,
    ERROR
}

data class RegisterFaceRequest(
    @SerializedName("image_base64")
    val imageBase64: String,
    @SerializedName("user_id")
    val userId: String
)

data class RegisterFaceResponse(
    val status: String,
    val message: String,
    @SerializedName("face_id")
    val faceId: String?,
    @SerializedName("db_id")
    val dbId: String?
)

data class DeleteFaceRequest(
    @SerializedName("user_id")
    val userId: String
)

data class DeleteFaceResponse(
    val status: String,
    val message: String,
    val deleted: Int?
)

data class UnlockByFaceRequest(
    @SerializedName("device_id")
    val deviceId: String
)

data class UnlockByFaceResponse(
    val success: Boolean,
    val message: String,
    val data: UnlockData?
)

data class UnlockData(
    @SerializedName("user_id")
    val userId: String,
    @SerializedName("device_id")
    val deviceId: String,
    val method: String,
    val timestamp: String
)
