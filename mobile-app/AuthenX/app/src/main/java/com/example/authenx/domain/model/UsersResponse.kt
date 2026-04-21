package com.example.authenx.domain.model

import kotlinx.serialization.Serializable

@Serializable
data class UsersResponse(
    val code: Int,
    val message: String,
    val count: Int,
    val users: List<User>
)
