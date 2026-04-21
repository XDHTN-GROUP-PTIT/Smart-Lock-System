package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

/**
 * Generic API Response wrapper
 */
data class ApiResponse<T>(
    val success: Boolean,
    val message: String?,
    val data: T? = null,
    val error: String? = null
)

/**
 * Statistics response from /logs/statistics endpoint
 */
data class AccessStatistics(
    @SerializedName("total_accesses")
    val totalAccesses: Int? = 0,
    @SerializedName("successful_accesses")
    val successfulAccesses: Int? = 0,
    @SerializedName("failed_accesses")
    val failedAccesses: Int? = 0,
    @SerializedName("access_by_method")
    val accessByMethod: Map<String, Int>? = emptyMap(),
    @SerializedName("access_by_day")
    val accessByDay: List<DailyAccess>? = emptyList(),
    @SerializedName("byMethod")
    val byMethod: List<AccessByMethod>? = emptyList(),
    @SerializedName("byResult")
    val byResult: List<AccessByResult>? = emptyList(),
    @SerializedName("dailyAccess")
    val dailyAccess: List<DailyAccess>? = emptyList(),
    @SerializedName("topUsers")
    val topUsers: List<TopUser>? = emptyList(),
    @SerializedName("recentAccess")
    val recentAccess: List<RecentAccess>? = emptyList()
)

data class AccessByMethod(
    @SerializedName("access_method")
    val accessMethod: String,
    val count: Int
)

data class AccessByResult(
    val result: String,
    val count: Int
)

data class TopUser(
    @SerializedName("user_id")
    val userId: String,
    @SerializedName("full_name")
    val fullName: String,
    @SerializedName("access_count")
    val accessCount: Int
)

data class RecentAccess(
    @SerializedName("_id")
    val id: String = "",
    @SerializedName("user_id")
    val userId: User? = null,
    @SerializedName("access_method")
    val accessMethod: String = "unknown",
    val result: String = "unknown",
    @SerializedName("device_id")
    val deviceId: String? = null,
    val time: String = "",
    val timestamp: String = ""
)

data class DailyAccess(
    val date: String,
    val count: Int
)

data class StatisticsResponse(
    val success: Boolean,
    val message: String?,
    val data: AccessStatistics
)
