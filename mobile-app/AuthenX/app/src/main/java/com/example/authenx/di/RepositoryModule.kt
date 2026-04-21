package com.example.authenx.di

import com.example.authenx.data.local.AuthManager
import com.example.authenx.data.remote.socket.SocketManager
import com.example.authenx.data.repository.AuthRepositoryImpl
import com.example.authenx.data.repository.BiometricRepositoryImpl
import com.example.authenx.data.repository.FaceRecognitionRepositoryImpl
import com.example.authenx.data.repository.OrganizationRepositoryImpl
import com.example.authenx.data.repository.StatisticsRepositoryImpl
import com.example.authenx.data.repository.UserRepositoryImpl
import com.example.authenx.data.repository.DeviceRepositoryImpl
import com.example.authenx.data.remote.source.AuthDataSource
import com.example.authenx.data.remote.source.BiometricDataSource
import com.example.authenx.data.remote.source.FaceRecognitionDataSource
import com.example.authenx.data.remote.source.OrganizationDataSource
import com.example.authenx.data.remote.source.StatisticsDataSource
import com.example.authenx.data.remote.source.UserDataSource
import com.example.authenx.data.remote.source.DeviceDataSource
import com.example.authenx.domain.repository.AuthRepository
import com.example.authenx.domain.repository.BiometricRepository
import com.example.authenx.domain.repository.FaceRecognitionRepository
import com.example.authenx.domain.repository.OrganizationRepository
import com.example.authenx.domain.repository.StatisticsRepository
import com.example.authenx.domain.repository.UserRepository
import com.example.authenx.domain.repository.DeviceRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object RepositoryModule {
    @Provides
    @Singleton
    fun provideAuthRepository(authDataSource: AuthDataSource): AuthRepository {
        return AuthRepositoryImpl(authDataSource)
    }
    
    @Provides
    @Singleton
    fun provideUserRepository(
        userDataSource: UserDataSource, 
        authManager: AuthManager,
        socketManager: SocketManager
    ): UserRepository {
        return UserRepositoryImpl(userDataSource, authManager, socketManager)
    }
    
    @Provides
    @Singleton
    fun provideStatisticsRepository(
        statisticsDataSource: StatisticsDataSource,
        authManager: AuthManager,
        socketManager: SocketManager
    ): StatisticsRepository {
        return StatisticsRepositoryImpl(statisticsDataSource, authManager, socketManager)
    }
    
    @Provides
    @Singleton
    fun provideFaceRecognitionRepository(
        faceRecognitionDataSource: FaceRecognitionDataSource
    ): FaceRecognitionRepository {
        return FaceRecognitionRepositoryImpl(faceRecognitionDataSource)
    }
    
    @Provides
    @Singleton
    fun provideBiometricRepository(
        biometricDataSource: BiometricDataSource
    ): BiometricRepository {
        return BiometricRepositoryImpl(biometricDataSource)
    }
    
    @Provides
    @Singleton
    fun provideOrganizationRepository(
        organizationDataSource: OrganizationDataSource
    ): OrganizationRepository {
        return OrganizationRepositoryImpl(organizationDataSource)
    }
    
    @Provides
    @Singleton
    fun provideDeviceRepository(
        deviceDataSource: DeviceDataSource
    ): DeviceRepository {
        return DeviceRepositoryImpl(deviceDataSource)
    }
}