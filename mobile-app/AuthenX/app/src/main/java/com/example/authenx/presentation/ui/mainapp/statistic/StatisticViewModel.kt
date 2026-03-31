package com.example.authenx.presentation.ui.mainapp.statistic

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.AccessStatistics
import com.example.authenx.domain.model.AdminStatsResponse
import com.example.authenx.domain.model.UserManagerStatsResponse
import com.example.authenx.domain.usecase.GetStatisticsUseCase
import com.example.authenx.domain.usecase.statistics.GetAdminStatsUseCase
import com.example.authenx.domain.usecase.statistics.GetOrganizationsUseCase
import com.example.authenx.domain.usecase.statistics.GetOrganizationStatsUseCase
import com.example.authenx.domain.usecase.statistics.GetUserManagerStatsUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import javax.inject.Inject

data class StatisticUiState(
    val isLoading: Boolean = false,
    val statistics: AccessStatistics? = null,
    val userManagerStats: UserManagerStatsResponse? = null,
    val adminStats: AdminStatsResponse? = null,
    val organizationStats: com.example.authenx.domain.model.OrganizationStatsResponse? = null,
    val organizations: List<com.example.authenx.domain.model.Organization> = emptyList(),
    val selectedOrganization: com.example.authenx.domain.model.Organization? = null,
    val error: String? = null,
    val todayCount: Int = 0,
    val weekCount: Int = 0,
    val monthCount: Int = 0,
    val averagePerDay: Float = 0f,
    val userRole: String? = null
)

@HiltViewModel
class StatisticViewModel @Inject constructor(
    private val getStatisticsUseCase: GetStatisticsUseCase,
    private val getUserManagerStatsUseCase: GetUserManagerStatsUseCase,
    private val getAdminStatsUseCase: GetAdminStatsUseCase,
    private val authManager: AuthManager,
    private val getOrganizationsUseCase: GetOrganizationsUseCase,
    private val getOrganizationStatsUseCase: GetOrganizationStatsUseCase
) : ViewModel() {

    companion object {
        private const val TAG = "StatisticViewModel"
    }

    private val _uiState = MutableStateFlow(StatisticUiState())
    val uiState: StateFlow<StatisticUiState> = _uiState.asStateFlow()

    init {
        val userRole = authManager.getUserRole()
        Log.d(TAG, "Init: User role = $userRole")
        _uiState.value = _uiState.value.copy(userRole = userRole)
        loadRoleBasedStatistics()
    }

    fun loadRoleBasedStatistics(days: Int = 7) {
        val role = authManager.getUserRole()
        Log.d(TAG, "Loading statistics for role: $role, days: $days")
        when (role) {
            "admin" -> loadAdminStats(days)
            "user_manager" -> loadUserManagerStats(days)
            else -> {
                Log.w(TAG, "Unknown role: $role, loading default statistics")
                loadStatistics()
            }
        }
    }

    private fun loadUserManagerStats(days: Int = 7) {
        viewModelScope.launch {
            Log.d(TAG, "Starting to load user_manager stats...")
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)
            
            getUserManagerStatsUseCase(days)
                .onSuccess { stats ->
                    Log.d(TAG, "User manager stats loaded successfully: $stats")
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        userManagerStats = stats,
                        error = null
                    )
                }
                .onFailure { error ->
                    Log.e(TAG, "Failed to load user manager stats", error)
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = error.message ?: "Failed to load statistics"
                    )
                }
        }
    }

    private fun loadAdminStats(days: Int = 7) {
        viewModelScope.launch {
            Log.d(TAG, "Starting to load admin stats...")
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)
            
            getAdminStatsUseCase(days)
                .onSuccess { stats ->
                    Log.d(TAG, "Admin stats loaded successfully: $stats")
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        adminStats = stats,
                        error = null
                    )
                    // Load organizations list
                    loadOrganizations()
                }
                .onFailure { error ->
                    Log.e(TAG, "Failed to load admin stats", error)
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = error.message ?: "Failed to load statistics"
                    )
                }
        }
    }

    private fun loadOrganizations() {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Loading organizations...")
                val response = getOrganizationsUseCase()
                Log.d(TAG, "Organizations loaded: ${response.data.size} orgs")
                _uiState.value = _uiState.value.copy(
                    organizations = response.data,
                    selectedOrganization = response.data.firstOrNull()
                )
                // Auto-load first organization stats
                response.data.firstOrNull()?.let { org ->
                    loadOrganizationStats(org.id)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load organizations", e)
            }
        }
    }

    fun selectOrganization(organization: com.example.authenx.domain.model.Organization) {
        Log.d(TAG, "Organization selected: ${organization.name}")
        _uiState.value = _uiState.value.copy(selectedOrganization = organization)
        loadOrganizationStats(organization.id)
    }

    private fun loadOrganizationStats(orgId: String) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Loading stats for organization: $orgId")
                _uiState.value = _uiState.value.copy(isLoading = true)
                val stats = getOrganizationStatsUseCase(orgId)
                Log.d(TAG, "Organization stats loaded: $stats")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    organizationStats = stats,
                    error = null
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load organization stats", e)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = e.message ?: "Failed to load organization statistics"
                )
            }
        }
    }

    fun loadStatistics(
        startDate: String? = null,
        endDate: String? = null,
        userId: String? = null
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)
            
            try {
                getStatisticsUseCase(startDate, endDate, userId).collect { statistics ->
                    if (statistics != null) {
                        val (today, week, month, avg) = calculateStats(statistics)
                        
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            statistics = statistics,
                            error = null,
                            todayCount = today as Int,
                            weekCount = week as Int,
                            monthCount = month as Int,
                            averagePerDay = avg as Float
                        )
                    } else {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            error = "Failed to load statistics"
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = e.message ?: "Unknown error occurred"
                )
            }
        }
    }

    private fun calculateStats(statistics: AccessStatistics): List<Any> {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
        val today = dateFormat.format(Date())
        
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -7)
        val weekAgo = dateFormat.format(calendar.time)
        
        calendar.time = Date()
        calendar.add(Calendar.DAY_OF_YEAR, -30)
        val monthAgo = dateFormat.format(calendar.time)

        var todayCount = 0
        var weekCount = 0
        var monthCount = 0

        statistics.dailyAccess?.forEach { daily ->
            val count = daily.count
            val date = daily.date
            
            if (date == today) {
                todayCount = count
            }
            
            if (date >= weekAgo) {
                weekCount += count
            }
            
            if (date >= monthAgo) {
                monthCount += count
            }
        }

        val averagePerDay = if (!statistics.dailyAccess.isNullOrEmpty()) {
            monthCount.toFloat() / 30
        } else {
            0f
        }

        return listOf(todayCount, weekCount, monthCount, averagePerDay)
    }

    fun refresh() {
        loadRoleBasedStatistics()
    }
}