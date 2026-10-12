package com.ciberdefensa.aura

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.system.OsConstants
import io.flutter.plugin.common.EventChannel
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.ArrayDeque
import java.util.concurrent.Executors

private data class PendingDnsEvent(
    val timestamp: Long,
    val domain: String,
    val action: String,
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String? = null,
    val destinationPort: Int? = null,
    val transportProtocol: String? = null,
    val publicDnsResolver: Boolean = false,
    val generation: Long,
)

private data class QueuedPlatformEvent(
    val generation: Long,
    val value: Map<String, Any>,
)

object AuraNetworkStream : EventChannel.StreamHandler {
    private const val MAX_PENDING_EVENTS = 512
    private const val DNS_SINKHOLE_ADDRESS = "10.0.0.3"

    private val lock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val uidResolver = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AuraDnsUidResolver").apply { isDaemon = true }
    }
    private val pendingDnsEvents = ArrayDeque<PendingDnsEvent>()
    private val pendingEvents = ArrayDeque<QueuedPlatformEvent>()
    private var applicationContext: Context? = null
    private var eventSink: EventChannel.EventSink? = null
    private var drainScheduled = false
    private var resolverScheduled = false
    private var eventGeneration = 0L

    fun setApplicationContext(context: Context) {
        applicationContext = context.applicationContext
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        synchronized(lock) {
            eventSink = events
            scheduleDrainLocked()
        }
    }

    override fun onCancel(arguments: Any?) {
        synchronized(lock) {
            eventSink = null
            pendingDnsEvents.clear()
            pendingEvents.clear()
            drainScheduled = false
        }
    }

    fun clearQueuedEvents() {
        synchronized(lock) {
            eventGeneration++
            pendingDnsEvents.clear()
            pendingEvents.clear()
        }
    }

    fun emitDnsEvent(
        domain: String,
        actionCode: Int,
        sourceAddress: String,
        sourcePort: Int,
    ) {
        val action = when (actionCode) {
            2 -> "DGA_ALERT"
            1, 3 -> "BLOCKED"
            else -> "ALLOWED"
        }
        synchronized(lock) {
            if (pendingDnsEvents.size == MAX_PENDING_EVENTS) pendingDnsEvents.removeFirst()
            pendingDnsEvents.addLast(
                PendingDnsEvent(
                    timestamp = System.currentTimeMillis(),
                    domain = domain,
                    action = action,
                    sourceAddress = sourceAddress,
                    sourcePort = sourcePort,
                    generation = eventGeneration,
                ),
            )
            if (!resolverScheduled) {
                resolverScheduled = true
                uidResolver.execute(::resolveQueuedEvents)
            }
        }
        if (actionCode == 3) {
            val context = synchronized(lock) { applicationContext }
            if (context != null) {
                com.aura.cyberdefense.AuraNotificationService.triggerDgaAlert(
                    context,
                    domain,
                )
            }
        }
    }

    fun emitSniEvent(domain: String, destinationAddress: String, destinationPort: Int) {
        enqueueEvent(
            PendingDnsEvent(
                timestamp = System.currentTimeMillis(),
                domain = domain,
                action = "SNI_OBSERVED",
                sourceAddress = "",
                sourcePort = 0,
                destinationAddress = destinationAddress,
                destinationPort = destinationPort,
                transportProtocol = "TCP",
                publicDnsResolver = isPublicDnsResolver(destinationAddress),
                generation = synchronized(lock) { eventGeneration },
            ),
        )
    }

    fun emitEncryptedDnsEvent(
        destinationAddress: String,
        destinationPort: Int,
        transportProtocol: String,
    ) {
        enqueueEvent(
            PendingDnsEvent(
                timestamp = System.currentTimeMillis(),
                domain = "Encrypted DNS attempt",
                action = "ENCRYPTED_DNS_BLOCKED",
                sourceAddress = "",
                sourcePort = 0,
                destinationAddress = destinationAddress,
                destinationPort = destinationPort,
                transportProtocol = transportProtocol,
                publicDnsResolver = isPublicDnsResolver(destinationAddress),
                generation = synchronized(lock) { eventGeneration },
            ),
        )
    }

    private fun enqueueEvent(event: PendingDnsEvent) {
        synchronized(lock) {
            if (pendingDnsEvents.size == MAX_PENDING_EVENTS) pendingDnsEvents.removeFirst()
            pendingDnsEvents.addLast(event)
            if (!resolverScheduled) {
                resolverScheduled = true
                uidResolver.execute(::resolveQueuedEvents)
            }
        }
    }

    private fun isPublicDnsResolver(address: String): Boolean {
        val candidate = try {
            InetAddress.getByName(address).address
        } catch (_: UnknownHostException) {
            return false
        }
        return PUBLIC_DNS_RESOLVER_ADDRESSES.any { candidate.contentEquals(it) }
    }

    private fun resolveQueuedEvents() {
        while (true) {
            val pending = synchronized(lock) {
                if (pendingDnsEvents.isEmpty()) {
                    resolverScheduled = false
                    null
                } else {
                    pendingDnsEvents.removeFirst()
                }
            } ?: return

            val event = buildMap<String, Any> {
                put(
                    "source_app",
                    if (pending.action == "SNI_OBSERVED" ||
                        pending.action == "ENCRYPTED_DNS_BLOCKED"
                    ) "uid-unavailable" else resolveSourceApp(
                        pending.sourceAddress,
                        pending.sourcePort,
                    ),
                )
                put("timestamp", pending.timestamp)
                put("requested_domain", pending.domain)
                put("action", pending.action)
                pending.destinationAddress?.let { put("destination_address", it) }
                pending.destinationPort?.let { put("destination_port", it) }
                pending.transportProtocol?.let { put("transport_protocol", it) }
                if (pending.destinationAddress != null) {
                    put("public_dns_resolver", pending.publicDnsResolver)
                }
            }
            val queued = synchronized(lock) {
                if (pending.generation != eventGeneration) {
                    false
                } else {
                    AuraVpnService.recordDnsAuditEvent(event)
                    if (pendingEvents.size == MAX_PENDING_EVENTS) pendingEvents.removeFirst()
                    pendingEvents.addLast(QueuedPlatformEvent(eventGeneration, event))
                    scheduleDrainLocked()
                    true
                }
            }
            if (!queued) continue
        }
    }

    private fun resolveSourceApp(sourceAddress: String, sourcePort: Int): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || sourcePort !in 1..65535) {
            return "uid-unavailable"
        }

        val context = applicationContext ?: return "uid-unavailable"
        return try {
            val connectivity =
                context.getSystemService(ConnectivityManager::class.java)
                    ?: return "uid-unavailable"
            val local = InetSocketAddress(InetAddress.getByName(sourceAddress), sourcePort)
            val remote = InetSocketAddress(InetAddress.getByName(DNS_SINKHOLE_ADDRESS), 53)
            val uid = connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_UDP, local, remote)
            if (uid < 0) return "uid-unavailable"
            context.packageManager.getPackagesForUid(uid)
                ?.takeIf { it.isNotEmpty() }
                ?.joinToString(",")
                ?: "uid:$uid"
        } catch (_: SecurityException) {
            "uid-unavailable"
        } catch (_: Exception) {
            "uid-unavailable"
        }
    }

    private fun scheduleDrainLocked() {
        if (drainScheduled || eventSink == null || pendingEvents.isEmpty()) return
        drainScheduled = true
        mainHandler.post(::drainOne)
    }

    private val PUBLIC_DNS_RESOLVER_ADDRESSES = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
        "149.112.112.112", "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111",
        "2606:4700:4700::1001", "2001:4860:4860::8888",
        "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
        "2620:119:35::35", "2620:119:35::53",
    ).map { InetAddress.getByName(it).address }

    private fun drainOne() {
        val sink: EventChannel.EventSink?
        val event: Map<String, Any>?
        synchronized(lock) {
            sink = eventSink
            val queuedEvent = if (sink == null) null else pendingEvents.pollFirst()
            if (queuedEvent == null) {
                drainScheduled = false
                return
            }
            event = queuedEvent.value.takeIf { queuedEvent.generation == eventGeneration }
            if (event == null) {
                drainScheduled = false
                scheduleDrainLocked()
                return
            }
        }

        try {
            sink?.success(event)
        } finally {
            synchronized(lock) {
                drainScheduled = false
                scheduleDrainLocked()
            }
        }
    }
}