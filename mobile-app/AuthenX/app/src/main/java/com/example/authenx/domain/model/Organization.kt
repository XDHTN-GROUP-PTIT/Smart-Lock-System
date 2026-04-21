package com.example.authenx.domain.model

import com.google.gson.annotations.SerializedName
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Organization(
    @SerialName("_id")
    @SerializedName("_id")
    val id: String,
    val name: String,
    val address: String? = null,
    val createdAt: String? = null,
    val updatedAt: String? = null
)

@Serializable
data class CreateOrganizationRequest(
    val name: String,
    val address: String? = null
)

@Serializable
data class CreateOrganizationResponse(
    val code: Int,
    val message: String,
    val organization: Organization? = null
)

@Serializable
data class OrganizationsResponse(
    val code: Int,
    val message: String,
    @SerialName("data")
    @SerializedName(value = "data", alternate = ["organizations"])
    val data: List<Organization>? = null
)
