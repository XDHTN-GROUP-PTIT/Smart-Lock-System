package com.example.authenx.presentation.ui.auth.login

import androidx.lifecycle.ViewModel
import com.example.authenx.domain.model.AuthResponse
import com.example.authenx.domain.model.LoginRequest
import com.example.authenx.domain.usecase.LoginUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject


@HiltViewModel
class LoginViewModel @Inject constructor(private val loginUseCase: LoginUseCase): ViewModel(){
    suspend fun login(email: String, password: String): AuthResponse {
        val loginRequest = LoginRequest(email, password)
        return loginUseCase(loginRequest)
    }
}