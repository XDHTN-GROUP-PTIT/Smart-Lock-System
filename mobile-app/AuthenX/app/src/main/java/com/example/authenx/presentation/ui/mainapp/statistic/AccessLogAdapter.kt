package com.example.authenx.presentation.ui.mainapp.statistic

import android.R
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.databinding.ItemAccessLogBinding
import com.example.authenx.domain.model.RecentAccess
import java.text.SimpleDateFormat
import java.util.Locale

class AccessLogAdapter : ListAdapter<RecentAccess, AccessLogAdapter.AccessLogViewHolder>(DiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AccessLogViewHolder {
        val binding = ItemAccessLogBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return AccessLogViewHolder(binding)
    }

    override fun onBindViewHolder(holder: AccessLogViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class AccessLogViewHolder(
        private val binding: ItemAccessLogBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        private val inputFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault())
        private val dateTimeFormat = SimpleDateFormat("dd/MM/yyyy • HH:mm:ss", Locale.getDefault())

        fun bind(log: RecentAccess) {
            binding.apply {
                // Display user name or "Unknown User" if null
                tvUserName.text = log.userId?.fullName ?: "Unknown User"
                
                // Parse and format timestamp
                try {
                    val date = inputFormat.parse(log.time)
                    tvDateTime.text = date?.let { dateTimeFormat.format(it) } ?: log.time
                } catch (e: Exception) {
                    tvDateTime.text = log.time
                }
                
                // Display status with color
                val isSuccess = log.result.lowercase().contains("success") || 
                               log.result.lowercase().contains("granted")
                
                tvStatus.text = if (isSuccess) "Success" else "Failed"
                
                val statusColor = if (isSuccess) {
                    R.color.holo_green_dark
                } else {
                    R.color.holo_red_dark
                }
                tvStatus.setTextColor(root.context.getColor(statusColor))
            }
        }
    }

    private class DiffCallback : DiffUtil.ItemCallback<RecentAccess>() {
        override fun areItemsTheSame(oldItem: RecentAccess, newItem: RecentAccess): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: RecentAccess, newItem: RecentAccess): Boolean {
            return oldItem == newItem
        }
    }
}