package com.example.authenx.presentation.ui.mainapp.select_user

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.authenx.R
import com.example.authenx.databinding.ItemSelectUserBinding
import com.example.authenx.domain.model.User
import java.util.Locale

class SelectUserAdapter(
    private val onUserSelected: (User) -> Unit
) : ListAdapter<User, SelectUserAdapter.SelectUserViewHolder>(DiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): SelectUserViewHolder {
        val binding = ItemSelectUserBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return SelectUserViewHolder(binding)
    }

    override fun onBindViewHolder(holder: SelectUserViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class SelectUserViewHolder(
        private val binding: ItemSelectUserBinding
    ) : RecyclerView.ViewHolder(binding.root) {

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
                
                root.setOnClickListener {
                    onUserSelected(user)
                }
            }
        }
    }

    private class DiffCallback : DiffUtil.ItemCallback<User>() {
        override fun areItemsTheSame(oldItem: User, newItem: User): Boolean = 
            oldItem.id == newItem.id
        override fun areContentsTheSame(oldItem: User, newItem: User): Boolean = 
            oldItem == newItem
    }
}
