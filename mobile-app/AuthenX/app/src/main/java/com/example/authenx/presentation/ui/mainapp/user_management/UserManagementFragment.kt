package com.example.authenx.presentation.ui.mainapp.user_management

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.authenx.R
import com.example.authenx.data.local.AuthManager
import com.example.authenx.databinding.FragmentUserManagementBinding
import com.example.authenx.domain.model.RfidCardInfo
import com.example.authenx.domain.model.User
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class UserManagementFragment : Fragment() {

    private var _binding: FragmentUserManagementBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: UserManagementViewModel by viewModels()
    private lateinit var userAdapter: UserAdapter
    
    @Inject
    lateinit var authManager: AuthManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentUserManagementBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupRecyclerView()
        setupSearchAndFilters()
        setOnClickListener()
        observeUiState()
        checkAdminPermission()
    }
    
    private fun checkAdminPermission() {
        val userRole = authManager.getUserRole()
        when (userRole) {
            "admin" -> {
                binding.fabAddManager.visibility = View.VISIBLE
                binding.fabAddUser.visibility = View.GONE
                binding.tvTitle.text = getString(R.string.manage_user_managers)
                binding.tvRoleDescription.text = getString(R.string.viewing_managers)
                binding.tvRoleDescription.visibility = View.VISIBLE
            }
            "user_manager" -> {
                binding.fabAddUser.visibility = View.VISIBLE
                binding.fabAddManager.visibility = View.GONE
                binding.tvTitle.text = getString(R.string.manage_users)
                binding.tvRoleDescription.text = getString(R.string.viewing_users)
                binding.tvRoleDescription.visibility = View.VISIBLE
            }
            else -> {
                binding.fabAddManager.visibility = View.GONE
                binding.fabAddUser.visibility = View.GONE
                binding.tvTitle.text = getString(R.string.user_management)
                binding.tvRoleDescription.visibility = View.GONE
            }
        }
    }
    
    private fun setupRecyclerView() {
        userAdapter = UserAdapter(
            onUserClick = { user ->
                Toast.makeText(requireContext(), "User: ${user.fullName}", Toast.LENGTH_SHORT).show()
            },
            onDeleteClick = { user ->
                showDeleteConfirmDialog(user)
            },
            onDeleteFingerprintClick = { user ->
                showDeleteFingerprintDialog(user)
            },
            onDeleteRfidClick = { user ->
                showDeleteRfidDialog(user)
            }
        )
        
        binding.rvUsers.apply {
            adapter = userAdapter
            layoutManager = LinearLayoutManager(requireContext())
        }
    }
    
    private fun showDeleteConfirmDialog(user: User) {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete User")
            .setMessage("Are you sure you want to delete ${user.fullName}?\nThis action cannot be undone.")
            .setPositiveButton("Delete") { dialog, _ ->
                viewModel.deleteUser(user.id)
                Toast.makeText(requireContext(), "✅ ${user.fullName} deleted successfully", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
    
    private fun showDeleteFingerprintDialog(user: User) {
        if (user.fingerprints.isEmpty()) {
            Toast.makeText(requireContext(), "No fingerprints to delete", Toast.LENGTH_SHORT).show()
            return
        }
        
        val fingerprintItems = user.fingerprints.map { 
            "Fingerprint ID: ${it.fingerprintId}" 
        }.toTypedArray()
        
        var selectedIndex = -1
        AlertDialog.Builder(requireContext())
            .setTitle("Delete Fingerprint for ${user.fullName}")
            .setSingleChoiceItems(fingerprintItems, -1) { _, which ->
                selectedIndex = which
            }
            .setPositiveButton("Delete") { dialog, _ ->
                if (selectedIndex >= 0) {
                    val selectedFingerprint = user.fingerprints[selectedIndex]
                    showFingerprintDeleteConfirmation(user, selectedFingerprint)
                }
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
    
    private fun showFingerprintDeleteConfirmation(user: User, fingerprint: com.example.authenx.domain.model.FingerprintInfo) {
        AlertDialog.Builder(requireContext())
            .setTitle("Confirm Delete")
            .setMessage("Delete fingerprint ID ${fingerprint.fingerprintId} for ${user.fullName}?")
            .setPositiveButton("Delete") { dialog, _ ->
                viewModel.deleteFingerprint(fingerprint.fingerprintId, user.id, fingerprint.deviceId)
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
    
    private fun showDeleteRfidDialog(user: User) {
        if (user.rfidCards.isEmpty()) {
            Toast.makeText(requireContext(), "No RFID cards to delete", Toast.LENGTH_SHORT).show()
            return
        }
        
        val rfidItems = user.rfidCards.map { 
            "Card UID: ${it.cardUid}" 
        }.toTypedArray()
        
        var selectedIndex = -1
        AlertDialog.Builder(requireContext())
            .setTitle("Delete RFID Card for ${user.fullName}")
            .setSingleChoiceItems(rfidItems, -1) { _, which ->
                selectedIndex = which
            }
            .setPositiveButton("Delete") { dialog, _ ->
                if (selectedIndex >= 0) {
                    val selectedCard = user.rfidCards[selectedIndex]
                    showRfidDeleteConfirmation(user, selectedCard)
                }
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
    
    private fun showRfidDeleteConfirmation(user: User, card: RfidCardInfo) {
        AlertDialog.Builder(requireContext())
            .setTitle("Confirm Delete")
            .setMessage("Delete RFID card ${card.cardUid} for ${user.fullName}?")
            .setPositiveButton("Delete") { dialog, _ ->
                viewModel.deleteRfid(card.cardUid, user.id)
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
    
    private fun setupSearchAndFilters() {
        // Search functionality
        binding.etSearch.addTextChangedListener { text ->
            viewModel.searchUsers(text?.toString() ?: "")
        }
    }
    
    private fun observeUiState() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    updateUi(state)
                }
            }
        }
    }
    
    private fun updateUi(state: UserManagementUiState) {
        // Update loading state
        binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE
        
        // Update user list
        userAdapter.submitList(state.filteredUsers)
        
        // Update user count
        binding.tvUserCount.text = getString(R.string.total_users, state.filteredUsers.size)
        
        // Show/hide empty state
        binding.layoutEmptyState.visibility = 
            if (state.filteredUsers.isEmpty() && !state.isLoading) View.VISIBLE else View.GONE
        binding.rvUsers.visibility = 
            if (state.filteredUsers.isEmpty() && !state.isLoading) View.GONE else View.VISIBLE
    }

    private fun setOnClickListener() {
        binding.btnBack.setOnClickListener {
            findNavController().popBackStack()
        }
        
        // Admin tạo user_manager (email + password)
        binding.fabAddManager.setOnClickListener {
            findNavController().navigate(R.id.action_userManagementFragment_to_registerFragment)
        }
        
        // user_manager tạo user (tên + SĐT)
        binding.fabAddUser.setOnClickListener {
            findNavController().navigate(R.id.action_userManagementFragment_to_createUserFragment)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}