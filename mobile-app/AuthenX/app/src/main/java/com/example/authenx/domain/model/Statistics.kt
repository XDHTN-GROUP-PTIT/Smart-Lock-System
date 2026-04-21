package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName

// Response cho User Manager Stats
data class UserManagerStatsResponse(
    val code: Int,
    val message: String,
    val data: UserManagerStats
)

data class UserManagerStats(
    @SerializedName("totalDevices")
    val totalDevices: Int = 0,
    @SerializedName("totalChildren")
    val totalChildren: Int = 0,
    @SerializedName("totalSecurityAlerts")
    val totalSecurityAlerts: Int = 0,
    @SerializedName("unreadNotifications")
    val unreadNotifications: Int = 0,
    @SerializedName("todayAccess")
    val todayAccess: Int = 0,
    @SerializedName("weekAccess")
    val weekAccess: Int = 0,
    @SerializedName("monthAccess")
    val monthAccess: Int = 0,
    @SerializedName("dailyAlerts")
    val dailyAlerts: List<DailyAlert> = emptyList(),
    @SerializedName("dailyAccess")
    val dailyAccess: List<DailyAlert> = emptyList(),
    @SerializedName("deviceStats")
    val deviceStats: List<DeviceStats> = emptyList(),
    @SerializedName("recentAccess")
    val recentAccess: List<RecentAccessLog> = emptyList()
)

data class DailyAlert(
    val date: String,
    val count: Int
)

data class RecentAccessLog(
    @SerializedName("user_name")
    val userName: String? = null,
    @SerializedName("device_id")
    val deviceId: String? = null,
    val timestamp: String? = null,
    @SerializedName("access_method")
    val accessMethod: String? = null,
    val status: String? = null
)

data class DeviceStats(
    @SerializedName("device_id")
    val deviceId: String,
    @SerializedName("device_name")
    val deviceName: String,
    val status: String,
    @SerializedName("total_access")
    val totalAccess: Int,
    @SerializedName("total_alerts")
    val totalAlerts: Int,
    @SerializedName("last_seen")
    val lastSeen: String?
)

// Response cho Admin Stats
data class AdminStatsResponse(
    val code: Int,
    val message: String,
    val data: AdminStats
)

data class AdminStats(
    @SerializedName("totalOrganizations")
    val totalOrganizations: Int = 0,
    @SerializedName("organizations")
    val organizations: List<OrganizationStats> = emptyList(),
    @SerializedName("topOrganizations")
    val topOrganizations: List<OrganizationStats> = emptyList(),
    @SerializedName("dailyAlerts")
    val dailyAlerts: List<DailyAlert> = emptyList(),
    @SerializedName("topDevices")
    val topDevices: List<TopDevice> = emptyList()
)

data class OrganizationStats(
    @SerializedName("org_id")
    val orgId: String,
    @SerializedName("org_name")
    val orgName: String,
    @SerializedName("total_devices")
    val totalDevices: Int,
    @SerializedName("total_user_manager")
    val totalUserManagers: Int,
    @SerializedName("total_alerts")
    val totalAlerts: Int
)

data class TopDevice(
    @SerializedName("_id")
    val deviceId: String,
    val count: Int
)

// Response cho Organization List (reuse Organization model from Organization.kt)
data class OrganizationListResponse(
    val code: Int,
    val message: String,
    val data: List<Organization>
)

// Response cho Organization Stats
data class OrganizationStatsResponse(
    val code: Int,
    val message: String,
    val data: OrganizationStatsData
)

data class OrganizationStatsData(
    val organization: OrganizationInfo,
    @SerializedName("totalDevices")
    val totalDevices: Int = 0,
    @SerializedName("totalUserManagers")
    val totalUserManagers: Int = 0,
    @SerializedName("totalUsers")
    val totalUsers: Int = 0,
    @SerializedName("todayAccess")
    val todayAccess: Int = 0,
    @SerializedName("weekAccess")
    val weekAccess: Int = 0,
    @SerializedName("monthAccess")
    val monthAccess: Int = 0,
    @SerializedName("dailyAccess")
    val dailyAccess: List<DailyAlert> = emptyList(),
    @SerializedName("deviceStats")
    val deviceStats: List<DeviceStats> = emptyList(),
    @SerializedName("recentAccess")
    val recentAccess: List<RecentAccessLog> = emptyList()
)

data class OrganizationInfo(
    val id: String,
    val name: String,
    val address: String? = null
)
