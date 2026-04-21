package com.example.authenx.data.remote.source

import com.example.authenx.BuildConfig
import com.example.authenx.data.local.AuthManager
import com.example.authenx.domain.model.CreateOrganizationRequest
import com.example.authenx.domain.model.CreateOrganizationResponse
import com.example.authenx.domain.model.OrganizationsResponse
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import javax.inject.Inject

class OrganizationDataSource @Inject constructor(
    private val httpClient: HttpClient,
    private val authManager: AuthManager
) {
    private val baseUrl = BuildConfig.API_BASE_URL

    suspend fun createOrganization(request: CreateOrganizationRequest): CreateOrganizationResponse {
        val token = authManager.getToken()
            ?: throw Exception("Admin authentication required")

        return httpClient.post("$baseUrl/organization/create") {
            bearerAuth(token)
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
    }

    suspend fun getAllOrganizations(): OrganizationsResponse {
        val token = authManager.getToken()
            ?: throw Exception("Authentication required")

        return httpClient.get("$baseUrl/organization") {
            bearerAuth(token)
        }.body()
    }

    suspend fun deleteOrganization(id: String): CreateOrganizationResponse {
        val token = authManager.getToken()
            ?: throw Exception("Admin authentication required")

        return httpClient.delete("$baseUrl/organization/delete/$id") {
            bearerAuth(token)
        }.body()
    }
}
