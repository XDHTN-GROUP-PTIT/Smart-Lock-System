package com.example.authenx.presentation.ui.mainapp.statistic.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.databinding.ItemOrganizationStatsBinding
import com.example.authenx.domain.model.OrganizationStats

class OrganizationStatsAdapter(
    private val onOrgClick: (OrganizationStats) -> Unit
) : ListAdapter<OrganizationStats, OrganizationStatsAdapter.OrganizationStatsViewHolder>(OrganizationStatsDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): OrganizationStatsViewHolder {
        val binding = ItemOrganizationStatsBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return OrganizationStatsViewHolder(binding)
    }

    override fun onBindViewHolder(holder: OrganizationStatsViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class OrganizationStatsViewHolder(
        private val binding: ItemOrganizationStatsBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(stats: OrganizationStats) {
            binding.apply {
                tvOrgName.text = stats.orgName
                tvTotalDevices.text = "Devices: ${stats.totalDevices}"
                tvTotalManagers.text = "Managers: ${stats.totalUserManagers}"
                tvTotalAlerts.text = "Alerts: ${stats.totalAlerts}"
                
                root.setOnClickListener {
                    onOrgClick(stats)
                }
            }
        }
    }

    private class OrganizationStatsDiffCallback : DiffUtil.ItemCallback<OrganizationStats>() {
        override fun areItemsTheSame(oldItem: OrganizationStats, newItem: OrganizationStats): Boolean {
            return oldItem.orgId == newItem.orgId
        }

        override fun areContentsTheSame(oldItem: OrganizationStats, newItem: OrganizationStats): Boolean {
            return oldItem == newItem
        }
    }
}
