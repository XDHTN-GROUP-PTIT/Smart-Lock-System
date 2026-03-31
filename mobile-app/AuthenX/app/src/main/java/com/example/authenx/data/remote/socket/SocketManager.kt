package com.example.authenx.data.remote.socket

import android.util.Log
import io.socket.client.IO
import io.socket.client.Socket
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import org.json.JSONObject
import java.net.URISyntaxException
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SocketManager @Inject constructor() {
    
    private var socket: Socket? = null
    private val TAG = "SocketManager"
    
    fun connect(serverUrl: String, token: String, userId: String? = null, role: String? = null) {
        try {
            if (socket?.connected() == true) {
                Log.d(TAG, "Socket already connected")
                return
            }
            
            val opts = IO.Options().apply {
                auth = mapOf("token" to token)
                reconnection = true
                reconnectionDelay = 1000
                reconnectionAttempts = 5
            }
            
            socket = IO.socket(serverUrl, opts)
            
            socket?.on(Socket.EVENT_CONNECT) {
                Log.d(TAG, "Socket connected")
                
                // Authenticate and join user room + org room + role room
                val authData = JSONObject().apply {
                    userId?.let { put("userId", it) }
                    role?.let { put("role", it) }
                }
                
                Log.d(TAG, "🔐 Sending authentication data: $authData")
                socket?.emit("authenticate", authData)
                Log.d(TAG, "✅ Sent authentication - userId: $userId, role: $role")
            }
            
            socket?.on(Socket.EVENT_DISCONNECT) {
                Log.d(TAG, "Socket disconnected")
            }
            
            socket?.on(Socket.EVENT_CONNECT_ERROR) { args ->
                Log.e(TAG, "Socket connection error: ${args.joinToString()}")
            }
            
            socket?.connect()
            
        } catch (e: URISyntaxException) {
            Log.e(TAG, "Socket URI error", e)
        } catch (e: Exception) {
            Log.e(TAG, "Socket connection error", e)
        }
    }
    
    fun disconnect() {
        socket?.disconnect()
        socket?.off()
        socket = null
        Log.d(TAG, "Socket disconnected and cleaned up")
    }
    
    fun onAccessLogCreated(): Flow<JSONObject?> = callbackFlow {
        val listener: (Array<Any>) -> Unit = { args ->
            try {
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    trySend(args[0] as JSONObject)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing access log event", e)
            }
        }
        
        socket?.on("access_log_created", listener)
        
        awaitClose {
            socket?.off("access_log_created", listener)
        }
    }
    
    fun onUserChanged(): Flow<Unit> = callbackFlow {
        val listener: (Array<Any>) -> Unit = { args ->
            if (args.isNotEmpty()) {
                Log.d(TAG, "User event received: ${args[0]}")
            }
            trySend(Unit)
        }
        
        // Listen to all user-related events
        socket?.on("user_created", listener)
        socket?.on("user_manager_created", listener)
        socket?.on("user_updated", listener)
        socket?.on("user_deleted", listener)
        socket?.on("user_manager_deleted", listener)
        
        awaitClose {
            socket?.off("user_created", listener)
            socket?.off("user_manager_created", listener)
            socket?.off("user_updated", listener)
            socket?.off("user_deleted", listener)
            socket?.off("user_manager_deleted", listener)
        }
    }
    
    fun onDoorUnlocked(): Flow<JSONObject?> = callbackFlow {
        val listener: (Array<Any>) -> Unit = { args ->
            try {
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    trySend(args[0] as JSONObject)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing door unlock event", e)
            }
        }
        
        socket?.on("door_unlocked", listener)
        
        awaitClose {
            socket?.off("door_unlocked", listener)
        }
    }
    
    fun onFingerprintEnrolled(): Flow<FingerprintEnrollEvent> = callbackFlow {
        val listener: (Array<Any>) -> Unit = { args ->
            try {
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    val json = args[0] as JSONObject
                    val event = FingerprintEnrollEvent(
                        userId = json.optString("user_id"),
                        fingerprintId = json.optInt("fingerprint_id"),
                        success = json.optBoolean("success", false),
                        message = json.optString("message")
                    )
                    trySend(event)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing fingerprint enroll event", e)
            }
        }
        
        socket?.on("fingerprint_enrolled", listener)
        
        awaitClose {
            socket?.off("fingerprint_enrolled", listener)
        }
    }
    
    fun onRfidEnrolled(): Flow<RfidEnrollEvent> = callbackFlow {
        val listener: (Array<Any>) -> Unit = { args ->
            try {
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    val json = args[0] as JSONObject
                    val event = RfidEnrollEvent(
                        userId = json.optString("userId"),
                        cardUid = json.optString("cardUid"),
                        success = json.optBoolean("success", false),
                        message = json.optString("message")
                    )
                    trySend(event)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing RFID enroll event", e)
            }
        }
        
        socket?.on("rfid_enroll_result", listener)
        
        awaitClose {
            socket?.off("rfid_enroll_result", listener)
        }
    }
    
    fun onSecurityAlert(): Flow<SecurityAlertEvent> = callbackFlow {
        Log.d(TAG, "Starting to listen for security_alert events...")
        
        val listener: (Array<Any>) -> Unit = { args ->
            Log.d(TAG, "Security alert event received! Args count: ${args.size}")
            try {
                if (args.isNotEmpty()) {
                    Log.d(TAG, "Raw security alert data: ${args[0]}")
                    if (args[0] is JSONObject) {
                        val json = args[0] as JSONObject
                        val event = SecurityAlertEvent(
                            notificationId = json.optString("notificationId"),
                            deviceId = json.optString("deviceId"),
                            method = json.optString("method"),
                            attemptCount = json.optInt("attemptCount"),
                            message = json.optString("message"),
                            timestamp = json.optString("timestamp")
                        )
                        trySend(event)
                        Log.d(TAG, "✅ Security alert parsed: ${event.message}")
                    } else {
                        Log.e(TAG, "Security alert data is not JSONObject: ${args[0]::class.java}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing security alert event", e)
            }
        }
        
        socket?.on("security_alert", listener)
        Log.d(TAG, "Security alert listener registered")
        
        awaitClose {
            socket?.off("security_alert", listener)
            Log.d(TAG, "Security alert listener removed")
        }
    }
    
    fun isConnected(): Boolean = socket?.connected() ?: false
}

data class FingerprintEnrollEvent(
    val userId: String,
    val fingerprintId: Int,
    val success: Boolean,
    val message: String?
)

data class RfidEnrollEvent(
    val userId: String,
    val cardUid: String?,
    val success: Boolean,
    val message: String?
)

data class SecurityAlertEvent(
    val notificationId: String,
    val deviceId: String,
    val method: String,
    val attemptCount: Int,
    val message: String,
    val timestamp: String
)
