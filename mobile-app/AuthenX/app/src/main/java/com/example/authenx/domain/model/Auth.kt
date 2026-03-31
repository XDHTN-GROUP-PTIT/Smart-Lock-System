package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

data class LoginRequest(
    val email: String,
    val password: String
)

data class RegisterRequest(
    val email: String,
    val password: String,
    val fullName: String,
    val confirmPassword: String,
    val phone: String? = null,
    @SerializedName("org_id")
    val orgId: String,
    val role: String = "user_manager"
)

data class AuthResponse(
    val code: Int,
    val message: String?,
    val token: String?,
    val user: User?
) {
    val success: Boolean
        get() = code == 200
}

data class RefreshTokenRequest(
    val refreshToken: String
)
