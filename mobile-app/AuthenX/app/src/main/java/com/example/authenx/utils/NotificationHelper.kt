package com.example.authenx.utils

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.authenx.R
import com.example.authenx.presentation.ui.MainActivity

object NotificationHelper {
    
    private const val CHANNEL_ID = "unlock_notifications"
    private const val CHANNEL_NAME = "Door Unlock Notifications"
    private const val CHANNEL_DESCRIPTION = "Notifications for door unlock events"
    private const val NOTIFICATION_ID = 1001
    
    private const val SECURITY_CHANNEL_ID = "security_alerts"
    private const val SECURITY_CHANNEL_NAME = "Security Alerts"
    private const val SECURITY_CHANNEL_DESCRIPTION = "Notifications for security alerts"
    private const val SECURITY_NOTIFICATION_ID = 1002
    
    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            
            // Unlock notifications channel
            val unlockChannel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH).apply {
                description = CHANNEL_DESCRIPTION
                enableVibration(true)
                setShowBadge(true)
            }
            notificationManager.createNotificationChannel(unlockChannel)
            
            // Security alerts channel
            val securityChannel = NotificationChannel(SECURITY_CHANNEL_ID, SECURITY_CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH).apply {
                description = SECURITY_CHANNEL_DESCRIPTION
                enableVibration(true)
                setShowBadge(true)
            }
            notificationManager.createNotificationChannel(securityChannel)
        }
    }
    
    fun showUnlockNotification(
        context: Context,
        method: String,
        userName: String,
        message: String
    ) {
        // Create intent to open app when notification is clicked
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        // Format method text
        val methodText = when(method) {
            "rfid" -> "RFID Card"
            "fingerprint" -> "Fingerprint"
            "face" -> "Face Recognition"
            "remote" -> "Remote Unlock"
            else -> method.uppercase()
        }
        
        // Build notification
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground) // You can change this icon
            .setContentTitle("🔓 Door Unlocked")
            .setContentText("Method: $methodText | User: $userName")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("$message\n\nMethod: $methodText\nUser: $userName")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setVibrate(longArrayOf(0, 500, 200, 500))
            .build()
        
        // Show notification
        try {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            e.printStackTrace()
        }
    }
    
    fun showSecurityAlertNotification(
        context: Context,
        message: String,
        deviceId: String,
        method: String
    ) {
        // Create intent to open app when notification is clicked
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        // Format method text
        val methodText = when(method) {
            "rfid" -> "RFID Card"
            "fingerprint" -> "Fingerprint"
            "face" -> "Face Recognition"
            else -> method.uppercase()
        }
        
        // Build notification
        val notification = NotificationCompat.Builder(context, SECURITY_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_fingerprint)
            .setContentTitle("🚨 Security Alert")
            .setContentText(message)
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("$message\n\nDevice: $deviceId\nMethod: $methodText")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setVibrate(longArrayOf(0, 500, 200, 500, 200, 500))
            .build()
        
        // Show notification
        try {
            NotificationManagerCompat.from(context).notify(SECURITY_NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            e.printStackTrace()
        }
    }
}

