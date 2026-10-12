package com.ciberdefensa.aura

import android.content.Context
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.IDN
import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit

private const val TELEMETRY_TAG = "AuraTelemetry"

object AuraTelemetryService {
    private const val PREFERENCES_NAME = "aura_privacy_preferences"
    private const val OPT_IN_KEY = "domain_telemetry_opt_in"
    private const val QUEUE_KEY = "domain_telemetry_queue"
    private const val LAST_EVENT_AT_KEY = "domain_telemetry_last_event_at"
    private const val FLUSH_WORK_NAME = "aura-domain-telemetry-flush"
    private const val MAX_BATCH_SIZE = 50
    private const val MIN_EVENT_INTERVAL_MS = 1_000L
    private const val FLUSH_INTERVAL_MINUTES = 5L
    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    private val EVENT_HOST_PATTERN = Regex(
        "^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+" +
            "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    )
    private val httpClient = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .callTimeout(30, TimeUnit.SECONDS)
        .build()
    private val lock = Any()
    private var activeCall: Call? = null

    data class Status(
        val optedIn: Boolean,
        val endpointConfigured: Boolean,
    )

    fun status(context: Context): Status {
        val preferences = preferences(context)
        return Status(
            optedIn = preferences.getBoolean(OPT_IN_KEY, false),
            endpointConfigured = isValidHttpsEndpoint(BuildConfig.AURA_TELEMETRY_ENDPOINT),
        )
    }

    fun setOptIn(context: Context, optedIn: Boolean) {
        check(
            !optedIn || isValidHttpsEndpoint(BuildConfig.AURA_TELEMETRY_ENDPOINT),
        ) {
            "Telemetry requires a valid HTTPS endpoint before opt-in."
        }
        val preferences = preferences(context)
        synchronized(lock) {
            check(preferences.edit().putBoolean(OPT_IN_KEY, optedIn).commit()) {
                "Could not persist the telemetry consent choice."
            }
            if (!optedIn) {
                activeCall?.cancel()
                activeCall = null
                check(preferences.edit().remove(QUEUE_KEY).remove(LAST_EVENT_AT_KEY).commit()) {
                    "Could not clear queued telemetry after consent withdrawal."
                }
            }
        }
        if (!optedIn) {
            WorkManager.getInstance(context.applicationContext)
                .cancelUniqueWork(FLUSH_WORK_NAME)
        }
    }

    fun recordDomainOutcome(
        context: Context,
        domain: String,
        outcome: String,
        source: String,
        modelVersion: String,
    ): Boolean {
        val normalizedDomain = IDN.toASCII(
            domain.trim().trimEnd('.').lowercase(Locale.ROOT),
        ).lowercase(Locale.ROOT)
        require(EVENT_HOST_PATTERN.matches(normalizedDomain)) {
            "A valid domain is required for telemetry."
        }
        require(outcome == "blocked" || outcome == "allowed") {
            "Telemetry outcome must be blocked or allowed."
        }
        require(source in setOf("ml", "blocklist", "allowlist")) {
            "Telemetry source must be ml, blocklist, or allowlist."
        }
        require(modelVersion.isNotBlank() && modelVersion.length <= 64) {
            "A valid model version is required for telemetry."
        }
        if (!isValidHttpsEndpoint(BuildConfig.AURA_TELEMETRY_ENDPOINT)) return false

        val preferences = preferences(context)
        val now = System.currentTimeMillis()
        val queueSize: Int
        synchronized(lock) {
            if (!preferences.getBoolean(OPT_IN_KEY, false)) return false
            val previousEventAt = preferences.getLong(LAST_EVENT_AT_KEY, 0L)
            if (
                now >= previousEventAt &&
                now - previousEventAt < MIN_EVENT_INTERVAL_MS
            ) {
                return false
            }

            val queue = readQueue(preferences)
            queue.put(
                JSONObject()
                    .put("hash", sha256(normalizedDomain))
                    .put("outcome", outcome)
                    .put("source", source)
                    .put("model_version", modelVersion)
                    .put("app_version", BuildConfig.VERSION_NAME)
                    .put("ts", now),
            )
            check(
                preferences.edit()
                    .putString(QUEUE_KEY, queue.toString())
                    .putLong(LAST_EVENT_AT_KEY, now)
                    .commit(),
            ) {
                "Could not persist queued telemetry."
            }
            queueSize = queue.length()
        }

        enqueueFlush(context, immediate = queueSize >= MAX_BATCH_SIZE)
        return true
    }

    suspend fun flush(context: Context): Boolean = withContext(Dispatchers.IO) {
        if (!status(context).optedIn ||
            !isValidHttpsEndpoint(BuildConfig.AURA_TELEMETRY_ENDPOINT)
        ) {
            return@withContext true
        }
        val queuedEvents = synchronized(lock) {
            val queue = readQueue(preferences(context))
            JSONArray().also { batch ->
                for (index in 0 until minOf(queue.length(), MAX_BATCH_SIZE)) {
                    batch.put(queue.getJSONObject(index))
                }
            }
        }
        if (queuedEvents.length() == 0) return@withContext true

        val request = Request.Builder()
            .url(BuildConfig.AURA_TELEMETRY_ENDPOINT)
            .header("User-Agent", "Aura-Mobile-Defens/${BuildConfig.VERSION_NAME}")
            .post(JSONObject().put("events", queuedEvents).toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()
        val call = httpClient.newCall(request)
        synchronized(lock) {
            if (!preferences(context).getBoolean(OPT_IN_KEY, false)) {
                return@withContext true
            }
            activeCall = call
        }
        try {
            call.execute().use { response ->
                if (!response.request.url.isHttps) {
                    throw IOException("Telemetry was redirected to a non-HTTPS endpoint.")
                }
                if (!response.isSuccessful) {
                    throw IOException("HTTP ${response.code} while uploading telemetry.")
                }
            }
        } finally {
            synchronized(lock) {
                if (activeCall === call) activeCall = null
            }
        }

        synchronized(lock) {
            val currentQueue = readQueue(preferences(context))
            val remaining = JSONArray()
            var consumed = 0
            for (index in 0 until currentQueue.length()) {
                val event = currentQueue.getJSONObject(index)
                if (
                    consumed < queuedEvents.length() &&
                    event.toString() == queuedEvents.getJSONObject(consumed).toString()
                ) {
                    consumed++
                } else {
                    remaining.put(event)
                }
            }
            if (consumed == queuedEvents.length()) {
                val editor = preferences(context).edit()
                if (remaining.length() == 0) {
                    editor.remove(QUEUE_KEY)
                } else {
                    editor.putString(QUEUE_KEY, remaining.toString())
                }
                check(editor.commit()) { "Could not remove uploaded telemetry events." }
            }
            if (remaining.length() > 0) enqueueFlush(context, immediate = true)
        }
        true
    }

    private fun enqueueFlush(context: Context, immediate: Boolean) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val request = OneTimeWorkRequestBuilder<AuraTelemetryFlushWorker>()
            .setConstraints(constraints)
            .setInitialDelay(
                if (immediate) 0 else FLUSH_INTERVAL_MINUTES,
                if (immediate) TimeUnit.SECONDS else TimeUnit.MINUTES,
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            FLUSH_WORK_NAME,
            if (immediate) ExistingWorkPolicy.REPLACE else ExistingWorkPolicy.KEEP,
            request,
        )
    }

    private fun readQueue(preferences: android.content.SharedPreferences): JSONArray =
        try {
            JSONArray(preferences.getString(QUEUE_KEY, "[]"))
        } catch (error: JSONException) {
            Log.e(TELEMETRY_TAG, "Discarding a malformed local telemetry queue.", error)
            JSONArray()
        }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(
            PREFERENCES_NAME,
            Context.MODE_PRIVATE,
        )

    private fun isValidHttpsEndpoint(value: String): Boolean =
        try {
            val uri = URI(value)
            uri.scheme.equals("https", ignoreCase = true) &&
                !uri.host.isNullOrBlank() &&
                uri.rawUserInfo == null
        } catch (_: java.net.URISyntaxException) {
            false
        }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

}

class AuraTelemetryFlushWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result =
        try {
            if (AuraTelemetryService.flush(applicationContext)) {
                Result.success()
            } else {
                Result.retry()
            }
        } catch (error: IOException) {
            if (!AuraTelemetryService.status(applicationContext).optedIn) {
                Result.success()
            } else {
                Log.e(
                    TELEMETRY_TAG,
                    "Telemetry upload failed; queued events were retained.",
                    error,
                )
                Result.retry()
            }
        } catch (error: JSONException) {
            Log.e(
                TELEMETRY_TAG,
                "Telemetry queue contains invalid event data.",
                error,
            )
            Result.failure()
        }
}
