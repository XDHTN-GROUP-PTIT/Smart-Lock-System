package com.example.authenx.presentation.ui.mainapp.device_list

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.PopupMenu
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.R
import com.example.authenx.databinding.ItemDeviceBinding
import com.example.authenx.domain.model.Device

class DeviceAdapter(
    private val onDeviceClick: (Device) -> Unit,
    private val onDeleteClick: (Device) -> Unit
) : ListAdapter<Device, DeviceAdapter.DeviceViewHolder>(DeviceDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DeviceViewHolder {
        val binding = ItemDeviceBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return DeviceViewHolder(binding, onDeviceClick, onDeleteClick)
    }

    override fun onBindViewHolder(holder: DeviceViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class DeviceViewHolder(
        private val binding: ItemDeviceBinding,
        private val onDeviceClick: (Device) -> Unit,
        private val onDeleteClick: (Device) -> Unit
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(device: Device) {
            binding.apply {
                tvDeviceId.text = device.deviceId
                tvDeviceModel.text = device.model ?: "Unknown Model"
                tvDeviceType.text = device.type ?: "smart_lock"

                // Status indicator
                val statusColor = when (device.status) {
                    "online" -> R.color.green_status
                    "offline" -> R.color.gray_status
                    "pending" -> R.color.orange_status
                    else -> R.color.gray_status
                }
                
                val statusText = when (device.status) {
                    "online" -> "Online"
                    "offline" -> "Offline"
                    "pending" -> "Pending"
                    "registered" -> "Registered"
                    "blocked" -> "Blocked"
                    else -> device.status ?: "Unknown"
                }

                tvDeviceStatus.text = statusText
                tvDeviceStatus.setTextColor(
                    ContextCompat.getColor(root.context, statusColor)
                )

                root.setOnClickListener {
                    onDeviceClick(device)
                }

                btnDeviceMenu.setOnClickListener { view ->
                    showPopupMenu(view, device)
                }
            }
        }

        private fun showPopupMenu(view: android.view.View, device: Device) {
            PopupMenu(view.context, view).apply {
                inflate(R.menu.menu_device_item)
                setOnMenuItemClickListener { menuItem ->
                    when (menuItem.itemId) {
                        R.id.action_delete_device -> {
                            onDeleteClick(device)
                            true
                        }
                        else -> false
                    }
                }
                show()
            }
        }
    }

    class DeviceDiffCallback : DiffUtil.ItemCallback<Device>() {
        override fun areItemsTheSame(oldItem: Device, newItem: Device): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: Device, newItem: Device): Boolean {
            return oldItem == newItem
        }
    }
}
