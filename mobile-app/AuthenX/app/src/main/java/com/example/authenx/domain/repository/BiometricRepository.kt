package com.example.authenx.domain.repository

import com.example.authenx.domain.model.DeleteFingerprintRequest
import com.example.authenx.domain.model.DeleteFingerprintResponse
import com.example.authenx.domain.model.EnrollFingerprintRequest
import com.example.authenx.domain.model.EnrollFingerprintResponse
import com.example.authenx.domain.model.EnrollRfidRequest
import com.example.authenx.domain.model.EnrollRfidResponse
import com.example.authenx.domain.model.DeleteRfidRequest
import com.example.authenx.domain.model.DeleteRfidResponse

interface BiometricRepository {
    suspend fun enrollFingerprint(request: EnrollFingerprintRequest): EnrollFingerprintResponse
    suspend fun deleteFingerprint(request: DeleteFingerprintRequest): DeleteFingerprintResponse
    suspend fun enrollRfid(request: EnrollRfidRequest): EnrollRfidResponse
    suspend fun deleteRfid(request: DeleteRfidRequest): DeleteRfidResponse
}
