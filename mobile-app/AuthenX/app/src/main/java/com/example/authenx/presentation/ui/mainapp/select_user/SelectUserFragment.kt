package com.example.authenx.presentation.ui.mainapp.select_user

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.os.bundleOf
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.authenx.R
import com.example.authenx.databinding.FragmentSelectUserBinding
import com.example.authenx.domain.model.User
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class SelectUserFragment : Fragment() {

    private var _binding: FragmentSelectUserBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: SelectUserViewModel by viewModels()
    private lateinit var selectUserAdapter: SelectUserAdapter
    
    private var deviceId: String? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSelectUserBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        deviceId = arguments?.getString("deviceId")
        
        setupToolbar()
        setupRecyclerView()
        setupSearch()
        observeUiState()
    }

    private fun setupToolbar() {
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigateUp()
        }
    }

    private fun setupRecyclerView() {
        selectUserAdapter = SelectUserAdapter { user ->
            navigateToEnrollBiometric(user)
        }
        
        binding.rvUsers.apply {
            adapter = selectUserAdapter
            layoutManager = LinearLayoutManager(requireContext())
        }
    }

    private fun setupSearch() {
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

    private fun updateUi(state: SelectUserUiState) {
        binding.progressBar.visibility = if (state.isLoading) View.VISIBLE else View.GONE
        
        selectUserAdapter.submitList(state.filteredUsers)
        
        binding.tvUserCount.text = getString(R.string.total_users, state.filteredUsers.size)
        
        binding.layoutEmptyState.visibility = 
            if (state.filteredUsers.isEmpty() && !state.isLoading) View.VISIBLE else View.GONE
        binding.rvUsers.visibility = 
            if (state.filteredUsers.isEmpty() && !state.isLoading) View.GONE else View.VISIBLE
        
        state.error?.let { error ->
            Toast.makeText(requireContext(), error, Toast.LENGTH_SHORT).show()
        }
    }

    private fun navigateToEnrollBiometric(user: User) {
        val bundle = bundleOf(
            "userId" to user.id,
            "userName" to user.fullName,
            "deviceId" to deviceId
        )
        
        // Check which fragment we're in to determine navigation
        val currentDestination = findNavController().currentDestination?.id
        if (currentDestination == R.id.selectUserForRfidFragment) {
            // Navigate to RFID enrollment
            findNavController().navigate(
                R.id.action_selectUserForRfidFragment_to_enrollRfidFragment,
                bundle
            )
        } else {
            // Navigate to fingerprint enrollment (default)
            findNavController().navigate(
                R.id.action_selectUserFragment_to_enrollBiometricFragment,
                bundle
            )
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
