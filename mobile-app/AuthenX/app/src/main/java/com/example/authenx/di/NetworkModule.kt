package com.example.authenx.di

import com.example.authenx.data.local.AuthManager
import com.example.authenx.data.remote.ApiService
import com.example.authenx.data.remote.source.AuthDataSource
import com.example.authenx.data.remote.source.DeviceDataSource
import com.example.authenx.data.remote.source.FaceRecognitionDataSource
import com.example.authenx.data.remote.source.OrganizationDataSource
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.defaultRequest
import io.ktor.client.plugins.logging.DEFAULT
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.serialization.gson.gson
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideHttpClient(): HttpClient {
        return HttpClient {
            install(ContentNegotiation) {
                gson {
                    setPrettyPrinting()
                    setLenient()
                }
            }
            install(Logging) {
                logger = Logger.DEFAULT
                level = LogLevel.ALL
            }
            install(HttpTimeout) {
                requestTimeoutMillis = 30000
                connectTimeoutMillis = 30000
                socketTimeoutMillis = 30000
            }
            defaultRequest {
                url(ApiService.BASE_URL)
            }
        }
    }
    
    @Provides
    @Singleton
    fun provideApiService(client: HttpClient): ApiService {
        return ApiService(client)
    }

    @Provides
    @Singleton
    fun provideAuthDatasource(client: HttpClient, authManager: AuthManager): AuthDataSource {
        return AuthDataSource(client, authManager)
    }
    
    @Provides
    @Singleton
    fun provideFaceRecognitionDataSource(client: HttpClient): FaceRecognitionDataSource {
        return FaceRecognitionDataSource(client)
    }
    
    @Provides
    @Singleton
    fun provideOrganizationDataSource(client: HttpClient, authManager: AuthManager): OrganizationDataSource {
        return OrganizationDataSource(client, authManager)
    }
    
    @Provides
    @Singleton
    fun provideDeviceDataSource(client: HttpClient, authManager: AuthManager): DeviceDataSource {
        return DeviceDataSource(client, authManager)
    }
}