package com.ciberdefensa.aura

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.IDN
import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

object AuraBlocklistService {
    private const val TAG = "AuraBlocklist"
    private const val WORK_NAME = "aura-daily-blocklist-update"
    private const val INITIAL_WORK_NAME = "aura-initial-blocklist-update"
    private const val MANIFEST_MAX_BYTES = 64 * 1024
    private const val FEED_MAX_BYTES = 32 * 1024 * 1024
    private const val CACHE_DIRECTORY = "blocklists"
    private const val MANIFEST_FEEDS_KEY = "feeds"
    private val SHA256_PATTERN = Regex("^[a-f0-9]{64}$")
    private val GENERATION_PATTERN = Regex("^[a-f0-9]{64}$")
    private val IPV4_PATTERN = Regex("^(?:\\d{1,3}\\.){3}\\d{1,3}$")
    private val LABEL_PATTERN = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    private val WHITESPACE_PATTERN = Regex("\\s+")

    private enum class Feed(val cacheName: String, val url: String) {
        URLHAUS(
            "urlhaus",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
        ),
        PHISHTANK(
            "phishtank",
            "https://data.phishtank.com/data/${android.net.Uri.encode(BuildConfig.PHISHTANK_APP_KEY)}/online-valid.json",
        ),
        OPENPHISH(
            "openphish",
            "https://openphish.com/feed.txt",
        ),
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .callTimeout(30, TimeUnit.SECONDS)
        .build()
    private val updateMutex = Mutex()
    private val stateLock = Any()

    @Volatile
    private var cacheDirectory: File? = null

    @Volatile
    private var cacheLoaded = false

    @Volatile
    private var blockedDomains: Set<String> = emptySet()

    fun initialize(context: Context) {
        val requestedDirectory =
            File(context.applicationContext.filesDir, CACHE_DIRECTORY)
        synchronized(stateLock) {
            if (cacheDirectory?.absolutePath != requestedDirectory.absolutePath) {
                cacheDirectory = requestedDirectory
                blockedDomains = emptySet()
                cacheLoaded = false
            }
        }
    }

    /**
     * Checks a normalized host and all its parent domains against the latest
     * verified cache. Throws when no verified generation is available.
     */
    fun isDomainBlocked(domain: String): Boolean {
        val host = normalizeDomain(domain)
            ?: throw IllegalArgumentException("A valid domain is required.")
        ensureCacheLoaded()
        val snapshot = blockedDomains
        if (snapshot.isEmpty()) {
            throw BlocklistUnavailableException(
                "No verified blocklist cache is available; ML evaluation is disabled.",
            )
        }

        var candidate = host
        while (true) {
            if (candidate in snapshot) return true
            val separator = candidate.indexOf('.')
            if (separator < 0) return false
            candidate = candidate.substring(separator + 1)
        }
    }

    suspend fun updateBlocklists(): Boolean = updateMutex.withLock {
        val manifestUrl = BuildConfig.AURA_BLOCKLIST_MANIFEST_URL
        if (!isHttpsUrl(manifestUrl)) {
            throw BlocklistConfigurationException(
                "AURA_BLOCKLIST_MANIFEST_URL must be a valid HTTPS URL.",
            )
        }
        if (BuildConfig.PHISHTANK_APP_KEY.isBlank()) {
            throw BlocklistConfigurationException(
                "PHISHTANK_APP_KEY is not configured.",
            )
        }

        val manifestBytes = download(manifestUrl, MANIFEST_MAX_BYTES)
        val expectedDigests = parseManifest(manifestBytes)
        val normalizedFeeds = linkedMapOf<Feed, Set<String>>()
        for (feed in Feed.entries) {
            val feedBytes = download(feed.url, FEED_MAX_BYTES)
            val actualDigest = sha256(feedBytes)
            if (actualDigest != expectedDigests.getValue(feed)) {
                throw BlocklistIntegrityException(
                    "SHA-256 mismatch for ${feed.cacheName}.",
                )
            }
            val parsedDomains = parseFeed(feed, feedBytes)
            if (parsedDomains.isEmpty()) {
                throw BlocklistIntegrityException(
                    "The verified ${feed.cacheName} feed contains no domains.",
                )
            }
            normalizedFeeds[feed] = parsedDomains
        }

        val manifestDigest = sha256(manifestBytes)
        val root = requireCacheDirectory()
        val generations = File(root, "generations")
        if (!generations.exists() && !generations.mkdirs()) {
            throw IOException("Could not create the blocklist generations directory.")
        }
        val generation = File(generations, manifestDigest)
        if (!generation.exists() || readGeneration(manifestDigest) == null) {
            if (generation.exists() && !generation.deleteRecursively()) {
                throw IOException("Could not replace an invalid blocklist generation.")
            }
            val temporaryGeneration = File(
                generations,
                ".${manifestDigest}.${UUID.randomUUID()}.tmp",
            )
            if (!temporaryGeneration.mkdirs()) {
                throw IOException("Could not create a temporary blocklist generation.")
            }
            try {
                for ((feed, domains) in normalizedFeeds) {
                    val content = domains.sorted().joinToString("\n", postfix = "\n")
                    val bytes = content.toByteArray(Charsets.UTF_8)
                    writeSynced(File(temporaryGeneration, "${feed.cacheName}.txt"), bytes)
                    writeSynced(
                        File(temporaryGeneration, "${feed.cacheName}.sha256"),
                        (sha256(bytes) + "\n").toByteArray(Charsets.US_ASCII),
                    )
                }
                moveAtomically(temporaryGeneration, generation)
            } catch (error: IOException) {
                temporaryGeneration.deleteRecursively()
                throw error
            }
        }

        val oldCurrent = readPointer(root, "current")
        val oldPrevious = readPointer(root, "previous")
        val changed = oldCurrent != manifestDigest
        if (oldCurrent != null && oldCurrent != manifestDigest) {
            writePointer(root, "previous", oldCurrent)
        }
        val previousToKeep = if (changed) oldCurrent else oldPrevious
        writePointer(root, "current", manifestDigest)
        synchronized(stateLock) {
            blockedDomains = normalizedFeeds.values.flatten().toSet()
            cacheLoaded = true
        }
        pruneGenerations(generations, manifestDigest, previousToKeep)
        changed
    }

    fun scheduleUpdates(context: Context) {
        if (
            !isHttpsUrl(BuildConfig.AURA_BLOCKLIST_MANIFEST_URL) ||
            BuildConfig.PHISHTANK_APP_KEY.isBlank()
        ) {
            Log.w(
                TAG,
                "Daily updates were not scheduled: configure the HTTPS manifest URL " +
                    "and PhishTank app key through Gradle environment variables.",
            )
            return
        }

        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val periodicRequest = PeriodicWorkRequestBuilder<AuraUpdateWorker>(
            24,
            TimeUnit.HOURS,
        )
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                30,
                TimeUnit.SECONDS,
            )
            .build()
        val initialRequest = OneTimeWorkRequestBuilder<AuraUpdateWorker>()
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                30,
                TimeUnit.SECONDS,
            )
            .build()

        WorkManager.getInstance(context.applicationContext)
            .enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                periodicRequest,
            )
        WorkManager.getInstance(context.applicationContext)
            .enqueueUniqueWork(
                INITIAL_WORK_NAME,
                ExistingWorkPolicy.KEEP,
                initialRequest,
            )
    }

    private suspend fun download(url: String, maximumBytes: Int): ByteArray =
        withContext(Dispatchers.IO) {
            if (!isHttpsUrl(url)) {
                throw BlocklistConfigurationException(
                    "Blocklist feeds must use valid HTTPS URLs.",
                )
            }
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "Aura-Mobile-Defens/1.0")
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.request.url.isHttps) {
                    throw IOException("An HTTPS blocklist request was redirected to HTTP.")
                }
                if (!response.isSuccessful) {
                    throw IOException("HTTP ${response.code} while downloading a blocklist.")
                }
                val body = response.body
                    ?: throw IOException("The blocklist response body is empty.")
                if (body.contentLength() > maximumBytes) {
                    throw IOException("Blocklist response exceeds its size limit.")
                }
                body.byteStream().use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (output.size() + count > maximumBytes) {
                            throw IOException("Blocklist response exceeds its size limit.")
                        }
                        output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
            }
        }

    private fun isHttpsUrl(value: String): Boolean {
        return try {
            val uri = URI(value)
            uri.scheme.equals("https", ignoreCase = true) &&
                !uri.host.isNullOrBlank() &&
                uri.rawUserInfo == null
        } catch (_: java.net.URISyntaxException) {
            false
        }
    }

    private fun parseManifest(bytes: ByteArray): Map<Feed, String> {
        val json = try {
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (error: JSONException) {
            throw BlocklistIntegrityException("The blocklist manifest is invalid JSON.", error)
        }
        val feeds = json.optJSONObject(MANIFEST_FEEDS_KEY)
            ?: throw BlocklistIntegrityException("The manifest has no feeds object.")
        return Feed.entries.associateWith { feed ->
            val entry = feeds.optJSONObject(feed.cacheName)
                ?: throw BlocklistIntegrityException(
                    "The manifest is missing ${feed.cacheName}.",
                )
            val digest = entry.optString("sha256").lowercase(Locale.ROOT)
            if (!SHA256_PATTERN.matches(digest)) {
                throw BlocklistIntegrityException(
                    "The manifest has an invalid SHA-256 for ${feed.cacheName}.",
                )
            }
            digest
        }
    }

    private fun parseFeed(feed: Feed, bytes: ByteArray): Set<String> {
        val domains = linkedSetOf<String>()
        when (feed) {
            Feed.URLHAUS -> {
                String(bytes, Charsets.UTF_8).lineSequence().forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) {
                        trimmed.split(WHITESPACE_PATTERN).forEach { token ->
                            normalizeFeedEntry(token)?.let(domains::add)
                        }
                    }
                }
            }

            Feed.OPENPHISH -> {
                String(bytes, Charsets.UTF_8).lineSequence().forEach { line ->
                    normalizeFeedEntry(line)?.let(domains::add)
                }
            }

            Feed.PHISHTANK -> {
                val json = try {
                    JSONArray(String(bytes, Charsets.UTF_8))
                } catch (error: JSONException) {
                    throw BlocklistIntegrityException(
                        "The PhishTank feed is invalid JSON.",
                        error,
                    )
                }
                for (index in 0 until json.length()) {
                    collectPhishTankUrls(json.opt(index), domains)
                }
            }
        }
        return domains
    }

    private fun collectPhishTankUrls(value: Any?, domains: MutableSet<String>) {
        when (value) {
            is JSONObject -> {
                val keys = value.keys()
                while (keys.hasNext()) {
                    val key = keys.next()
                    val child = value.opt(key)
                    if (key.equals("url", ignoreCase = true) && child is String) {
                        normalizeFeedEntry(child)?.let(domains::add)
                    } else {
                        collectPhishTankUrls(child, domains)
                    }
                }
            }

            is JSONArray -> {
                for (index in 0 until value.length()) {
                    collectPhishTankUrls(value.opt(index), domains)
                }
            }
        }
    }

    private fun normalizeFeedEntry(rawEntry: String): String? {
        var candidate = rawEntry.trim().trim('"', '\'', ',', ';')
        if (candidate.isEmpty() || candidate.startsWith("#")) return null
        if (candidate.startsWith("*.")) candidate = candidate.substring(2)
        val uri = try {
            if (candidate.contains("://")) URI(candidate) else null
        } catch (_: java.net.URISyntaxException) {
            return null
        }
        if (uri != null) {
            if (!uri.scheme.equals("http", true) && !uri.scheme.equals("https", true)) {
                return null
            }
            candidate = uri.host ?: return null
        }
        return normalizeDomain(candidate)
    }

    private fun normalizeDomain(rawDomain: String): String? {
        var candidate = rawDomain.trim().lowercase(Locale.ROOT).trimEnd('.')
        if (candidate.startsWith("*.")) candidate = candidate.substring(2)
        if (candidate.isEmpty() || candidate.contains('/') || candidate.contains(':')) {
            return null
        }
        val ascii = try {
            IDN.toASCII(candidate, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii.length > 253 || !ascii.contains('.')) return null
        if (IPV4_PATTERN.matches(ascii)) return null
        val labels = ascii.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 || !LABEL_PATTERN.matches(it) }) {
            return null
        }
        return ascii
    }

    private fun ensureCacheLoaded() {
        if (cacheLoaded) return
        synchronized(stateLock) {
            if (cacheLoaded) return
            val root = requireCacheDirectory()
            val current = readPointer(root, "current")
            val previous = readPointer(root, "previous")
            val loaded = listOfNotNull(current, previous)
                .distinct()
                .firstNotNullOfOrNull(::readGeneration)
            if (loaded == null) {
                blockedDomains = emptySet()
                Log.e(TAG, "No verified blocklist generation is available.")
            } else {
                blockedDomains = loaded
            }
            cacheLoaded = true
        }
    }

    private fun readGeneration(generationId: String): Set<String>? {
        val root = requireCacheDirectory()
        val generation = File(File(root, "generations"), generationId)
        val domains = linkedSetOf<String>()
        for (feed in Feed.entries) {
            val dataFile = File(generation, "${feed.cacheName}.txt")
            val digestFile = File(generation, "${feed.cacheName}.sha256")
            if (!dataFile.isFile || !digestFile.isFile) return null
            val bytes = dataFile.readBytes()
            val expected = digestFile.readText(Charsets.US_ASCII).trim()
            if (!SHA256_PATTERN.matches(expected) || sha256(bytes) != expected) {
                Log.e(TAG, "Cached ${feed.cacheName} blocklist failed SHA-256 validation.")
                return null
            }
            String(bytes, Charsets.UTF_8).lineSequence()
                .filter(String::isNotBlank)
                .forEach { line ->
                    val normalized = normalizeDomain(line)
                    if (normalized == null || normalized != line) return null
                    domains.add(normalized)
                }
        }
        return domains.takeIf { it.isNotEmpty() }
    }

    private fun readPointer(root: File, name: String): String? {
        val pointer = File(root, name)
        if (!pointer.isFile) return null
        val value = pointer.readText(Charsets.US_ASCII).trim()
        return value.takeIf(GENERATION_PATTERN::matches)
    }

    private fun writePointer(root: File, name: String, value: String) {
        val temporary = File(root, ".$name.${UUID.randomUUID()}.tmp")
        writeSynced(temporary, (value + "\n").toByteArray(Charsets.US_ASCII))
        moveAtomically(temporary, File(root, name))
    }

    private fun writeSynced(destination: File, bytes: ByteArray) {
        destination.outputStream().use { stream ->
            stream.write(bytes)
            stream.flush()
            stream.fd.sync()
        }
    }

    private fun moveAtomically(source: File, destination: File) {
        try {
            Os.rename(source.absolutePath, destination.absolutePath)
        } catch (error: ErrnoException) {
            throw IOException("Could not atomically replace ${destination.name}.", error)
        }
    }

    private fun pruneGenerations(
        generations: File,
        current: String,
        previous: String?,
    ) {
        generations.listFiles()
            ?.filter { it.isDirectory && it.name != current && it.name != previous }
            ?.forEach { oldGeneration ->
                if (GENERATION_PATTERN.matches(oldGeneration.name)) {
                    oldGeneration.deleteRecursively()
                }
            }
    }

    private fun requireCacheDirectory(): File {
        val directory = cacheDirectory
            ?: throw BlocklistConfigurationException(
                "AuraBlocklistService.initialize(context) must be called first.",
            )
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Could not create the blocklist cache directory.")
        }
        return directory
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    class BlocklistException(message: String, cause: Throwable? = null) :
        IOException(message, cause)

    class BlocklistConfigurationException(message: String) :
        IllegalStateException(message)

    class BlocklistIntegrityException(message: String, cause: Throwable? = null) :
        BlocklistException(message, cause)

    class BlocklistUnavailableException(message: String) :
        IllegalStateException(message)

}
