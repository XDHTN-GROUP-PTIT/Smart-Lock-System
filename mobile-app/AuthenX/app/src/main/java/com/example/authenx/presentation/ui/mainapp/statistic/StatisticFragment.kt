package com.example.authenx.presentation.ui.mainapp.statistic

import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.authenx.R
import com.example.authenx.databinding.FragmentStatisticBinding
import com.example.authenx.presentation.ui.mainapp.statistic.adapter.DeviceStatsAdapter
import com.github.mikephil.charting.components.XAxis
import com.github.mikephil.charting.data.BarData
import com.github.mikephil.charting.data.BarDataSet
import com.github.mikephil.charting.data.BarEntry
import com.github.mikephil.charting.formatter.IndexAxisValueFormatter
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class StatisticFragment : Fragment() {

    companion object {
        private const val TAG = "StatisticFragment"
    }

    private var _binding: FragmentStatisticBinding? = null
    private val binding get() = _binding!!
    private val viewModel: StatisticViewModel by viewModels()

    private val deviceStatsAdapter by lazy {
        DeviceStatsAdapter { device ->
            Toast.makeText(requireContext(), "Device: ${device.deviceName}", Toast.LENGTH_SHORT).show()
        }
    }
    
    private var isSpinnerInitialized = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentStatisticBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        setOnClickListener()
        observeUiState()
        setupAccessLog()
    }

    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    Log.d(TAG, "UI State: role=${state.userRole}, userManagerStats=${state.userManagerStats != null}")
                    binding.progressBar.isVisible = state.isLoading
                    
                    // Handle role-based display
                    when (state.userRole) {
                        "user_manager" -> {
                            state.userManagerStats?.let { stats ->
                                updateUserManagerView(stats)
                            }
                        }
                        "admin" -> {
                            state.adminStats?.let { stats ->
                                Log.d(TAG, "Updating admin view with ${stats.data.organizations.size} organizations")
                                updateAdminView(stats)
                            }
                            // Setup organization selector if organizations are loaded
                            if (state.organizations.isNotEmpty()) {
                                setupOrganizationSelector(state.organizations, state.selectedOrganization)
                            }
                            // Show organization stats
                            state.organizationStats?.let { orgStats ->
                                if (orgStats.data != null) {
                                    updateOrganizationStatsView(orgStats)
                                } else {
                                    Log.e(TAG, "Organization stats data is null")
                                }
                            }
                        }
                        else -> {
                            // Default: regular statistics
                            state.statistics?.let { stats ->
                                updateStatCards(state)
                                stats.dailyAccess?.takeLast(7)?.let { dailyData ->
                                    if (dailyData.isNotEmpty()) {
                                        updateChart(dailyData)
                                    }
                                }
                                updateAccessLog(stats.recentAccess)
                            }
                        }
                    }
                    
                    state.error?.let { error ->
                        Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun updateStatCards(state: StatisticUiState) {
        with(binding) {
            tvTotalAccessToday.text = state.todayCount.toString()
            tvTotalAccessWeek.text = state.weekCount.toString()
            tvTotalAccessMonth.text = state.monthCount.toString()
            tvAveragePerDay.text = String.format("%.1f", state.averagePerDay)
        }
    }

    private fun updateChart(dailyData: List<com.example.authenx.domain.model.DailyAccess>) {
        if (dailyData.isEmpty()) {
            setupMockData()
            return
        }

        val entries = dailyData.mapIndexed { index, daily ->
            BarEntry((index + 1).toFloat(), daily.count.toFloat())
        }

        val dataSet = BarDataSet(entries, "Access count (7 days)").apply {
            color = Color.parseColor("#4CAF50")
            valueTextColor = Color.BLACK
            valueTextSize = 12f
        }

        val barData = BarData(dataSet)

        with(binding.chartAccess) {
            data = barData
            description.isEnabled = false
            legend.isEnabled = false

            setFitBars(true)
            animateY(800)

            xAxis.apply {
                position = XAxis.XAxisPosition.BOTTOM
                setDrawGridLines(false)
                granularity = 1f
                // Parse and format dates properly
                val labels = dailyData.map { 
                    try {
                        val parts = it.date.split("-")
                        if (parts.size == 3) {
                            "${parts[2]}/${parts[1]}" // DD/MM format
                        } else {
                            it.date.substring(5) // Fallback to MM-DD
                        }
                    } catch (e: Exception) {
                        it.date
                    }
                }
                valueFormatter = IndexAxisValueFormatter(labels)
            }

            axisLeft.axisMinimum = 0f
            axisRight.isEnabled = false
            invalidate()
        }
    }

    private fun setupMockData() {
        val entries = listOf(
            BarEntry(1f, 12f),
            BarEntry(2f, 18f),
            BarEntry(3f, 9f),
            BarEntry(4f, 25f),
            BarEntry(5f, 15f),
            BarEntry(6f, 22f),
            BarEntry(7f, 19f)
        )

        val dataSet = BarDataSet(entries, "Access count (7 days)").apply {
            color = Color.parseColor("#4CAF50")
            valueTextColor = Color.BLACK
            valueTextSize = 12f
        }

        val barData = BarData(dataSet)

        with (binding) {
            chartAccess.apply {
                data = barData
                description.isEnabled = false
                legend.isEnabled = false

                setFitBars(true)
                animateY(800)

                xAxis.apply {
                    position = XAxis.XAxisPosition.BOTTOM
                    setDrawGridLines(false)
                    granularity = 1f
                    valueFormatter = IndexAxisValueFormatter(
                        listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
                    )
                }

                axisLeft.axisMinimum = 0f
                axisRight.isEnabled = false
                invalidate()
            }

            tvTotalAccessToday.text = "18"
            tvTotalAccessWeek.text = "120"
            tvTotalAccessMonth.text = "420"
            tvAveragePerDay.text = "17.5"
        }
    }

    private fun setOnClickListener () {
        with(binding) {
            btnBack.setOnClickListener {
                findNavController().popBackStack()
            }
            
            btnRefresh.setOnClickListener {
                viewModel.refresh()
            }
        }
    }

    private fun setupAccessLog() {
        // Initialize RecyclerView with adapter
        val adapter = AccessLogAdapter()
        binding.rvAccessLog.adapter = adapter
        binding.rvAccessLog.layoutManager = LinearLayoutManager(requireContext())
    }

    private fun setupDeviceStats() {
        binding.rvDeviceStats.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = deviceStatsAdapter
        }
    }

    private fun updateUserManagerView(stats: com.example.authenx.domain.model.UserManagerStatsResponse) {
        Log.d(TAG, "Updating user manager view")
        with(binding) {
            // Update overview cards with correct data from API
            tvTotalAccessToday.text = stats.data.todayAccess.toString()
            tvTotalAccessWeek.text = stats.data.weekAccess.toString()
            tvTotalAccessMonth.text = stats.data.monthAccess.toString()
            
            // Calculate average per day
            val avgPerDay = if (stats.data.monthAccess > 0) {
                stats.data.monthAccess.toFloat() / 30
            } else {
                0f
            }
            tvAveragePerDay.text = String.format("%.1f", avgPerDay)
            
            // Show device stats section
            layoutDeviceStats.isVisible = true
            setupDeviceStats()
            deviceStatsAdapter.submitList(stats.data.deviceStats)
            
            // Update chart with daily access data if available
            if (stats.data.dailyAccess.isNotEmpty()) {
                val entries = stats.data.dailyAccess.mapIndexed { index, daily ->
                    BarEntry((index + 1).toFloat(), daily.count.toFloat())
                }
                
                val dataSet = BarDataSet(entries, "Daily Access (${stats.data.dailyAccess.size} days)").apply {
                    color = Color.parseColor("#4CAF50")
                    valueTextColor = Color.BLACK
                    valueTextSize = 12f
                }
                
                val barData = BarData(dataSet)
                
                chartAccess.apply {
                    data = barData
                    description.isEnabled = false
                    legend.isEnabled = false
                    setFitBars(true)
                    animateY(800)
                    
                    xAxis.apply {
                        position = XAxis.XAxisPosition.BOTTOM
                        setDrawGridLines(false)
                        granularity = 1f
                        val labels = stats.data.dailyAccess.map { 
                            try {
                                val parts = it.date.split("-")
                                if (parts.size == 3) "${parts[2]}/${parts[1]}" else it.date
                            } catch (e: Exception) {
                                it.date
                            }
                        }
                        valueFormatter = IndexAxisValueFormatter(labels)
                    }
                    
                    axisLeft.axisMinimum = 0f
                    axisRight.isEnabled = false
                    invalidate()
                }
            } else {
                // Show empty chart message
                Log.d(TAG, "No daily access data available")
            }
            
            // Update recent access logs
            if (stats.data.recentAccess.isNotEmpty()) {
                Log.d(TAG, "Mapping recent access logs: ${stats.data.recentAccess.size} items")
                // Convert RecentAccessLog to RecentAccess format
                val recentAccessList = stats.data.recentAccess.mapNotNull { log ->
                    try {
                        com.example.authenx.domain.model.RecentAccess(
                            id = "${log.deviceId}_${log.timestamp}",
                            userId = com.example.authenx.domain.model.User(
                                id = "",
                                email = "",
                                fullName = log.userName ?: "Unknown",
                                phone = "",
                                role = "user"
                            ),
                            accessMethod = log.accessMethod ?: "unknown",
                            result = log.status ?: "unknown",
                            deviceId = log.deviceId ?: "",
                            time = log.timestamp ?: "",
                            timestamp = log.timestamp ?: ""
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Error mapping access log: ${e.message}", e)
                        null
                    }
                }
                
                val adapter = rvAccessLog.adapter as? AccessLogAdapter
                adapter?.submitList(recentAccessList)
                Log.d(TAG, "Updated recent access logs: ${recentAccessList.size} items")
            }
        }
    }

    private fun updateAccessLog(recentAccess: List<com.example.authenx.domain.model.RecentAccess>?) {
        val adapter = binding.rvAccessLog.adapter as? AccessLogAdapter
        // Take only the latest 10 access logs
        adapter?.submitList(recentAccess?.take(10) ?: emptyList())
    }

    private fun updateAdminView(stats: com.example.authenx.domain.model.AdminStatsResponse) {
        Log.d(TAG, "Updating admin view")
        with(binding) {
            // Show organization selector
            cardOrganizationSelector.isVisible = true
            
            // Hide device stats for overview
            layoutDeviceStats.isVisible = false
            
            // Show basic admin overview stats
            tvTotalAccessToday.text = stats.data.totalOrganizations.toString()
            tvTotalAccessWeek.text = stats.data.organizations.sumOf { it.totalDevices }.toString()
            tvTotalAccessMonth.text = stats.data.organizations.sumOf { it.totalUserManagers }.toString()
            tvAveragePerDay.text = stats.data.organizations.sumOf { it.totalAlerts }.toString()
            
            // Clear access log and chart (will be filled when org is selected)
            (rvAccessLog.adapter as? AccessLogAdapter)?.submitList(emptyList())
        }
    }

    private fun setupOrganizationSelector(
        organizations: List<com.example.authenx.domain.model.Organization>,
        selectedOrg: com.example.authenx.domain.model.Organization?
    ) {
        // Prevent re-initialization if already setup
        if (isSpinnerInitialized) {
            return
        }
        
        val adapter = ArrayAdapter(
            requireContext(),
            android.R.layout.simple_spinner_item,
            organizations.map { it.name }
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        
        binding.spinnerOrganization.adapter = adapter
        
        // Set selected item
        selectedOrg?.let { org ->
            val position = organizations.indexOfFirst { it.id == org.id }
            if (position >= 0) {
                binding.spinnerOrganization.setSelection(position, false) // false = don't trigger listener
            }
        }
        
        // Handle selection
        binding.spinnerOrganization.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            private var lastSelectedPosition = -1
            
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                // Skip if same position
                if (position == lastSelectedPosition) {
                    return
                }
                lastSelectedPosition = position
                
                val selectedOrganization = organizations[position]
                Log.d(TAG, "Organization selected: ${selectedOrganization.name}")
                viewModel.selectOrganization(selectedOrganization)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
                // Do nothing
            }
        }
        
        isSpinnerInitialized = true
    }

    private fun updateOrganizationStatsView(stats: com.example.authenx.domain.model.OrganizationStatsResponse) {
        Log.d(TAG, "Updating organization stats view")
        try {
            val statsData = stats.data ?: run {
                Log.e(TAG, "Organization stats data is null")
                Toast.makeText(requireContext(), "Failed to load organization stats", Toast.LENGTH_SHORT).show()
                return
            }
            
            val organization = statsData.organization ?: run {
                Log.e(TAG, "Organization info is null")
                Toast.makeText(requireContext(), "Organization info missing", Toast.LENGTH_SHORT).show()
                return
            }
            
            Log.d(TAG, "Updating stats for: ${organization.name}")
            
        with(binding) {
            // Update overview cards with organization's access data
            tvTotalAccessToday.text = statsData.todayAccess.toString()
            tvTotalAccessWeek.text = statsData.weekAccess.toString()
            tvTotalAccessMonth.text = statsData.monthAccess.toString()
            
            // Calculate average per day
            val avgPerDay = if (statsData.monthAccess > 0) {
                statsData.monthAccess.toFloat() / 30
            } else {
                0f
            }
            tvAveragePerDay.text = String.format("%.1f", avgPerDay)
            
            // Show device stats section
            layoutDeviceStats.isVisible = true
            setupDeviceStats()
            deviceStatsAdapter.submitList(statsData.deviceStats)
            
            // Update chart with daily access data
            if (statsData.dailyAccess.isNotEmpty()) {
                val entries = statsData.dailyAccess.mapIndexed { index, daily ->
                    BarEntry((index + 1).toFloat(), daily.count.toFloat())
                }
                
                val dataSet = BarDataSet(entries, "Daily Access (${statsData.dailyAccess.size} days)").apply {
                    color = Color.parseColor("#4CAF50")
                    valueTextColor = Color.BLACK
                    valueTextSize = 12f
                }
                
                val barData = BarData(dataSet)
                
                chartAccess.apply {
                    data = barData
                    description.isEnabled = false
                    legend.isEnabled = false
                    setFitBars(true)
                    animateY(800)
                    
                    xAxis.apply {
                        position = XAxis.XAxisPosition.BOTTOM
                        setDrawGridLines(false)
                        granularity = 1f
                        val labels = statsData.dailyAccess.map { 
                            try {
                                val parts = it.date.split("-")
                                if (parts.size == 3) "${parts[2]}/${parts[1]}" else it.date
                            } catch (e: Exception) {
                                it.date
                            }
                        }
                        valueFormatter = IndexAxisValueFormatter(labels)
                    }
                    
                    axisLeft.axisMinimum = 0f
                    axisRight.isEnabled = false
                    invalidate()
                }
            }
            
            // Update recent access logs
            if (statsData.recentAccess.isNotEmpty()) {
                Log.d(TAG, "Mapping recent access logs: ${statsData.recentAccess.size} items")
                val recentAccessList = statsData.recentAccess.mapNotNull { log ->
                    try {
                        com.example.authenx.domain.model.RecentAccess(
                            id = "${log.deviceId}_${log.timestamp}",
                            userId = com.example.authenx.domain.model.User(
                                id = "",
                                email = "",
                                fullName = log.userName ?: "Unknown",
                                phone = "",
                                role = "user"
                            ),
                            accessMethod = log.accessMethod ?: "unknown",
                            result = log.status ?: "unknown",
                            deviceId = log.deviceId ?: "",
                            time = log.timestamp ?: "",
                            timestamp = log.timestamp ?: ""
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Error mapping access log: ${e.message}", e)
                        null
                    }
                }
                
                val adapter = rvAccessLog.adapter as? AccessLogAdapter
                adapter?.submitList(recentAccessList)
                Log.d(TAG, "Updated recent access logs: ${recentAccessList.size} items")
            }
        }
        } catch (e: Exception) {
            Log.e(TAG, "Error updating organization stats view", e)
            Toast.makeText(requireContext(), "Error displaying stats: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
