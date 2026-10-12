package com.ciberdefensa.aura

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import java.io.IOException
import org.json.JSONException

class AuraUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result {
        try {
            AuraBlocklistService.initialize(applicationContext)
            val updated = AuraBlocklistService.updateBlocklists()
            if (updated) showUpdatedNotification()
            return Result.success()
        } catch (error: AuraBlocklistService.BlocklistConfigurationException) {
            Log.e(TAG, "Blocklist update configuration is incomplete.", error)
            return Result.failure()
        } catch (error: IOException) {
            Log.e(TAG, "Blocklist update failed; the verified cache was retained.", error)
            return if (runAttemptCount < MAX_RETRIES - 1) Result.retry() else Result.failure()
        } catch (error: JSONException) {
            Log.e(TAG, "Blocklist update returned invalid data.", error)
            return if (runAttemptCount < MAX_RETRIES - 1) Result.retry() else Result.failure()
        }
    }

    private fun showUpdatedNotification() {
        val notificationManager =
            applicationContext.getSystemService(Context.NOTIFICATION_SERVICE)
                as NotificationManager
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            notificationManager.getNotificationChannel(NOTIFICATION_CHANNEL_ID) == null
        ) {
            notificationManager.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL_ID,
                    NOTIFICATION_CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
        val notification = NotificationCompat.Builder(
            applicationContext,
            NOTIFICATION_CHANNEL_ID,
        )
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(NOTIFICATION_TITLE)
            .setContentText(NOTIFICATION_TEXT)
            .setStyle(NotificationCompat.BigTextStyle().bigText(NOTIFICATION_TEXT))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()
        try {
            notificationManager.notify(NOTIFICATION_ID, notification)
        } catch (error: SecurityException) {
            Log.w(TAG, "Notification permission is unavailable.", error)
        }
    }

    private companion object {
        const val TAG = "AuraUpdateWorker"
        const val MAX_RETRIES = 3
        const val NOTIFICATION_CHANNEL_ID = "com.aura.mobile.defens.vpn"
        const val NOTIFICATION_CHANNEL_NAME = "Aura Centinela"
        const val NOTIFICATION_ID = 8817
        const val NOTIFICATION_TITLE =
            "Aura Mobile Defens · Blocklists actualizadas"
        const val NOTIFICATION_TEXT =
            "Se descargaron y verificaron las listas de amenazas URLhaus, " +
                "PhishTank y OpenPhish."
    }
}
