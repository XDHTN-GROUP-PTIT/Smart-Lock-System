package com.example.authenx.presentation.ui.mainapp.statistic.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.R
import com.example.authenx.databinding.ItemDeviceStatsBinding
import com.example.authenx.domain.model.DeviceStats
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DeviceStatsAdapter(
    private val onDeviceClick: (DeviceStats) -> Unit
) : ListAdapter<DeviceStats, DeviceStatsAdapter.DeviceStatsViewHolder>(DeviceStatsDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DeviceStatsViewHolder {
        val binding = ItemDeviceStatsBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return DeviceStatsViewHolder(binding)
    }

    override fun onBindViewHolder(holder: DeviceStatsViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class DeviceStatsViewHolder(
        private val binding: ItemDeviceStatsBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(stats: DeviceStats) {
            binding.apply {
                tvDeviceId.text = stats.deviceId
                tvDeviceName.text = stats.deviceName
                tvTotalAccess.text = stats.totalAccess.toString()
                tvTotalAlerts.text = stats.totalAlerts.toString()
                
                // Status badge
                when (stats.status.lowercase()) {
                    "online" -> {
                        tvStatus.text = "Online"
                        tvStatus.setBackgroundColor(
                            ContextCompat.getColor(root.context, R.color.success)
                        )
                    }
                    "offline" -> {
                        tvStatus.text = "Offline"
                        tvStatus.setBackgroundColor(
                            ContextCompat.getColor(root.context, R.color.error)
                        )
                    }
                    else -> {
                        tvStatus.text = "Unknown"
                        tvStatus.setBackgroundColor(
                            ContextCompat.getColor(root.context, R.color.gray)
                        )
                    }
                }
                
                // Last seen
                stats.lastSeen?.let { lastSeen ->
                    try {
                        val inputFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault())
                        val outputFormat = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
                        val date = inputFormat.parse(lastSeen)
                        tvLastSeen.text = "Last seen: ${date?.let { outputFormat.format(it) } ?: "Unknown"}"
                    } catch (e: Exception) {
                        tvLastSeen.text = "Last seen: Unknown"
                    }
                } ?: run {
                    tvLastSeen.text = "Last seen: Unknown"
                }
                
                root.setOnClickListener {
                    onDeviceClick(stats)
                }
            }
        }
    }

    private class DeviceStatsDiffCallback : DiffUtil.ItemCallback<DeviceStats>() {
        override fun areItemsTheSame(oldItem: DeviceStats, newItem: DeviceStats): Boolean {
            return oldItem.deviceId == newItem.deviceId
        }

        override fun areContentsTheSame(oldItem: DeviceStats, newItem: DeviceStats): Boolean {
            return oldItem == newItem
        }
    }
}
