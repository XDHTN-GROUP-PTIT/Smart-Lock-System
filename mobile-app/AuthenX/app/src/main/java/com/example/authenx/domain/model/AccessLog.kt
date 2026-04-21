package com.example.authenx.domain.model

import java.sql.Timestamp

data class AccessLog(
    val id: String,
    val userName: String,
    val timestamp: Timestamp,
    val status: Boolean,
    val avatarRes: Int
)