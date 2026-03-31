package com.example.authenx.presentation.ui.mainapp.user_management

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.PopupMenu
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.R
import com.example.authenx.databinding.UserItemBinding
import com.example.authenx.domain.model.User
import java.text.SimpleDateFormat
import java.util.Locale

class UserAdapter(
    private val onUserClick: (User) -> Unit = {},
    private val onDeleteClick: (User) -> Unit = {},
    private val onDeleteFingerprintClick: (User) -> Unit = {},
    private val onDeleteRfidClick: (User) -> Unit = {}
) : ListAdapter<User, UserAdapter.UserViewHolder>(DiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): UserViewHolder {
        val binding = UserItemBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return UserViewHolder(binding)
    }

    override fun onBindViewHolder(holder: UserViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class UserViewHolder(private val binding: UserItemBinding) :
        RecyclerView.ViewHolder(binding.root) {

        private val dateFormat = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())

        fun bind(user: User) {
            binding.apply {
                tvUserName.text = user.fullName
                tvUserId.text = if (user.email.isNotEmpty()) user.email else user.phone
                
                val roleText = when (user.role) {
                    "user_manager" -> "Manager"
                    "admin" -> "Admin"
                    "user" -> "User"
                    else -> user.role.replaceFirstChar { 
                        if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString() 
                    }
                }
                tvUserRole.text = roleText
                
                tvUserRole.setBackgroundResource(
                    when (user.role) {
                        "admin" -> R.color.primary_color
                        "user_manager" -> R.color.secondary_color
                        else -> android.R.color.darker_gray
                    }
                )
                tvUserRole.setTextColor(
                    root.context.getColor(R.color.white)
                )
                
                // Show fingerprint info
                if (user.fingerprints.isNotEmpty()) {
                    layoutFingerprint.visibility = View.VISIBLE
                    tvFingerprintCount.text = user.fingerprints.size.toString()
                } else {
                    layoutFingerprint.visibility = View.GONE
                }
                
                // Show RFID info
                if (user.rfidCards.isNotEmpty()) {
                    layoutRfid.visibility = View.VISIBLE
                    tvRfidCount.text = user.rfidCards.size.toString()
                } else {
                    layoutRfid.visibility = View.GONE
                }
                
                root.setOnClickListener { onUserClick(user) }
                
                // Setup menu button click
                btnMore.setOnClickListener { view ->
                    showPopupMenu(view, user)
                }
            }
        }
        
        private fun showPopupMenu(view: View, user: User) {
            val popup = PopupMenu(view.context, view)
            popup.menuInflater.inflate(R.menu.user_item_menu, popup.menu)
            
            // Hide edit option
            popup.menu.findItem(R.id.action_edit)?.isVisible = false
            
            // Show/hide fingerprint delete option based on whether user has fingerprints
            popup.menu.findItem(R.id.action_delete_fingerprint)?.isVisible = user.fingerprints.isNotEmpty()
            
            // Show/hide RFID delete option based on whether user has RFID cards
            popup.menu.findItem(R.id.action_delete_rfid)?.isVisible = user.rfidCards.isNotEmpty()
            
            popup.setOnMenuItemClickListener { menuItem ->
                when (menuItem.itemId) {
                    R.id.action_delete_fingerprint -> {
                        onDeleteFingerprintClick(user)
                        true
                    }
                    R.id.action_delete_rfid -> {
                        onDeleteRfidClick(user)
                        true
                    }
                    R.id.action_delete -> {
                        onDeleteClick(user)
                        true
                    }
                    else -> false
                }
            }
            
            popup.show()
        }
    }

    private class DiffCallback : DiffUtil.ItemCallback<User>() {
        override fun areItemsTheSame(oldItem: User, newItem: User): Boolean = oldItem.id == newItem.id
        override fun areContentsTheSame(oldItem: User, newItem: User): Boolean = oldItem == newItem
    }
}