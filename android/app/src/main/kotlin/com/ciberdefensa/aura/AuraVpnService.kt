package com.ciberdefensa.aura

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.aura.cyberdefense.AuraNotificationService
import hev.htproxy.TProxyService
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.Collections
import java.util.HashSet
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AuraVpnService : VpnService() {
    companion object {
        const val ACTION_STATE = "com.ciberdefensa.aura.VPN_STATE"
        private const val SOCKS5_HOST = "socks5.tun2socks.local"
        private const val SOCKS5_PORT = 1080
        private const val THREAT_FEED_URL =
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        private const val NOTIFICATION_CHANNEL = "com.aura.mobile.defens.vpn"
        private const val NOTIFICATION_CHANNEL_NAME = "Aura Centinela"
        private const val NOTIFICATION_ID = 8816
        private const val NOTIFICATION_TEXT =
            "Protección agéntica local en tiempo real operando sin interrupciones."
        private const val VPN_STATE_PREFERENCES = "aura_vpn_state"
        private const val PANIC_ISOLATION_KEY = "panic_isolation_active"
        private const val MAX_BLOCKED_IPS = 8192
        private val dnsMetricsLock = Any()
        @Volatile private var activeService: AuraVpnService? = null
        private var auditedDnsRequests = 0L
        private var blockedDnsRequests = 0L
        private var lastDnsDomain = ""
        private var lastDnsAction = ""
        @JvmStatic
        fun protectSocket(socketFd: Int): Boolean =
            activeService?.protect(socketFd) ?: false

        @JvmStatic
        fun engagePanicIsolation(): Boolean =
            activeService?.enterPanicIsolation() ?: false

        @JvmStatic
        fun resumeTunnel(): Boolean = activeService?.resumeTunnelForwarding() ?: false

        @JvmStatic
        fun clearDnsAuditMemory() {
            synchronized(dnsMetricsLock) {
                auditedDnsRequests = 0
                blockedDnsRequests = 0
                lastDnsDomain = ""
                lastDnsAction = ""
                activeService?.scheduleNotificationUpdate()
            }
        }

        fun recordDnsAuditEvent(event: Map<String, Any>) {
            val action = event["action"] as? String ?: return
            val domain = event["requested_domain"] as? String ?: return
            val service: AuraVpnService?
            synchronized(dnsMetricsLock) {
                auditedDnsRequests++
                if (action == "BLOCKED" || action == "DGA_ALERT") blockedDnsRequests++
                lastDnsDomain = domain
                lastDnsAction = action
                service = activeService
            }
            service?.scheduleNotificationUpdate()
        }
    }

    private val worker = Executors.newSingleThreadExecutor()
    private val feedRefresh: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor()
    private val integrityMonitor: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor()
    private val blockedIps: MutableSet<String> =
        Collections.synchronizedSet(HashSet())
    private val startRequested = AtomicBoolean(false)
    private val notificationHandler = Handler(Looper.getMainLooper())
    private var notificationUpdatePending = false
    private var vpnInterface: ParcelFileDescriptor? = null
    private var integrityCheckScheduled = false
    private var feedRefreshScheduled = false
    @Volatile private var panicIsolationActive = false
    @Volatile private var tunnelStarted = false

    override fun onCreate() {
        super.onCreate()
        activeService = this
        AuraNetworkStream.setApplicationContext(applicationContext)
        panicIsolationActive = getSharedPreferences(
            VPN_STATE_PREFERENCES,
            MODE_PRIVATE,
        ).getBoolean(PANIC_ISOLATION_KEY, false)
    }

    override fun onStartCommand(
        intent: android.content.Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        ensureNotificationChannel()
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        if (!verifyIntegrityOrStop()) return Service.START_NOT_STICKY
        if (integrityMonitor.isShutdown) return Service.START_NOT_STICKY
        if (!integrityCheckScheduled) {
            integrityCheckScheduled = true
            integrityMonitor.scheduleWithFixedDelay(
                { verifyIntegrityOrStop() },
                30,
                30,
                TimeUnit.SECONDS,
            )
        }
        if (panicIsolationActive) {
            if (vpnInterface == null && startRequested.compareAndSet(false, true)) {
                worker.execute { establishPanicIsolationInterface() }
            }
            reportState(false, "Aislamiento de emergencia activo; forwarding detenido.")
            return Service.START_STICKY
        }
        if (tunnelStarted) {
            reportState(true, "El escudo VPN ya estaba activo.")
        } else if (startRequested.compareAndSet(false, true)) {
            worker.execute { startTunnel() }
        }
        return Service.START_STICKY
    }

    override fun onDestroy() {
        feedRefresh.shutdownNow()
        integrityMonitor.shutdownNow()
        worker.shutdownNow()
        if (tunnelStarted) {
            TProxyService.TProxyStopService()
            tunnelStarted = false
        }
        if (activeService === this) activeService = null
        notificationHandler.removeCallbacksAndMessages(null)
        vpnInterface?.close()
        vpnInterface = null
        stopService(android.content.Intent(this, AuraNotificationService::class.java))
        super.onDestroy()
    }

    private fun verifyIntegrityOrStop(): Boolean {
        val report = try {
            AuraAntiTampering.inspect(this)
        } catch (exception: Exception) {
            Log.e("AuraVPN", "No se pudo comprobar la integridad del servicio.", exception)
            mapOf("isSecure" to false)
        }
        if (report["isSecure"] == true) return true

        Log.e("AuraVPN", "Deteniendo el túnel por fallo de integridad.")
        if (tunnelStarted) {
            TProxyService.TProxyStopService()
            tunnelStarted = false
        }
        reportState(false, "Escudo detenido por fallo de integridad.")
        stopSelf()
        return false
    }

    private fun startTunnel() {
        var established: ParcelFileDescriptor? = null
        try {
            val proxyAddress = resolveProxyAddress()
            verifySocks5(proxyAddress)
            replaceBlockedIps(downloadThreatFeed())

            established = createVpnBuilder().establish()
                ?: throw IOException("Android no estableció la interfaz VPN.")

            val configFile = File(filesDir, "aura-hev-socks5.yml")
            configFile.writeText(
                """
                tunnel:
                  name: aura0
                  mtu: 1500
                  ipv4: 10.0.0.2
                  ipv6: 'fd00::2'
                  icmp: 'off'
                socks5:
                  port: $SOCKS5_PORT
                  address: $proxyAddress
                  udp: 'udp'
misc:
    log-level: error
mapdns:
    address: 10.0.0.3
    port: 53
    network: 100.64.0.0
    netmask: 255.192.0.0
    cache-size: 8192
                """.trimIndent(),
            )

            vpnInterface = established
            TProxyService.TProxySetBlockedIps(blockedIpSnapshot())
            if (!TProxyService.TProxyStartService(configFile.absolutePath, established.fd)) {
                throw IOException("El motor tun2socks no pudo iniciar.")
            }
            tunnelStarted = true
            scheduleFeedRefresh()
            reportState(true, "Escudo VPN iniciado.")
            Log.i("AuraVPN", "Hev tun2socks conectado al proxy SOCKS5.")
        } catch (e: Exception) {
            Log.e("AuraVPN", "No se pudo iniciar el escudo VPN.", e)
            if (tunnelStarted) TProxyService.TProxyStopService()
            tunnelStarted = false
            established?.close()
            vpnInterface = null
            startRequested.set(false)
            reportState(false, e.message ?: "No se pudo iniciar el escudo.")
            stopSelf()
        }
    }

    @Synchronized
    private fun enterPanicIsolation(): Boolean {
        if (panicIsolationActive) return vpnInterface != null
        if (!tunnelStarted || vpnInterface == null) return false

        return try {
            val persisted = getSharedPreferences(VPN_STATE_PREFERENCES, MODE_PRIVATE)
                .edit()
                .putBoolean(PANIC_ISOLATION_KEY, true)
                .commit()
            if (!persisted) return false
            if (!TProxyService.TProxyStopService()) {
                getSharedPreferences(VPN_STATE_PREFERENCES, MODE_PRIVATE)
                    .edit()
                    .putBoolean(PANIC_ISOLATION_KEY, false)
                    .commit()
                return false
            }
            tunnelStarted = false
            panicIsolationActive = true
            startRequested.set(false)
            reportState(false, "Aislamiento de emergencia activo; forwarding detenido.")
            updateForegroundNotification()
            true
        } catch (exception: Exception) {
            getSharedPreferences(VPN_STATE_PREFERENCES, MODE_PRIVATE)
                .edit()
                .putBoolean(PANIC_ISOLATION_KEY, false)
                .commit()
            panicIsolationActive = false
            Log.e("AuraVPN", "No se pudo detener el forwarding del túnel.", exception)
            false
        }
    }

    @Synchronized
    private fun resumeTunnelForwarding(): Boolean {
        if (!panicIsolationActive) return tunnelStarted
        val tun = vpnInterface ?: return false
        val configFile = File(filesDir, "aura-hev-socks5.yml")
        if (!configFile.isFile) return false

        return try {
            TProxyService.TProxySetBlockedIps(blockedIpSnapshot())
            if (!TProxyService.TProxyStartService(configFile.absolutePath, tun.fd)) {
                return false
            }
            val cleared = getSharedPreferences(VPN_STATE_PREFERENCES, MODE_PRIVATE)
                .edit()
                .putBoolean(PANIC_ISOLATION_KEY, false)
                .commit()
            if (!cleared) {
                TProxyService.TProxyStopService()
                return false
            }
            panicIsolationActive = false
            tunnelStarted = true
            startRequested.set(true)
            scheduleFeedRefresh()
            reportState(true, "Forwarding del túnel VPN restablecido.")
            updateForegroundNotification()
            true
        } catch (exception: Exception) {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
            Log.e("AuraVPN", "No se pudo reanudar el forwarding del túnel.", exception)
            false
        }
    }

    private fun establishPanicIsolationInterface() {
        var established: ParcelFileDescriptor? = null
        try {
            established = createVpnBuilder().establish()
                ?: throw IOException("Android no restableció la interfaz VPN aislada.")
            vpnInterface = established
            reportState(false, "Aislamiento de emergencia activo; tráfico en descarte.")
            updateForegroundNotification()
        } catch (exception: Exception) {
            Log.e("AuraVPN", "No se pudo restablecer la interfaz aislada.", exception)
            established?.close()
            vpnInterface = null
            startRequested.set(false)
            reportState(false, exception.message ?: "Falló el aislamiento de red.")
        }
    }

    private fun createVpnBuilder(): Builder = Builder()
        .setSession("Aura Mobile Defens")
        .setMtu(1500)
        .addAddress("10.0.0.2", 24)
        .addAddress("fd00::2", 64)
        // Full routes capture TCP and UDP on both IP families for tunnel inspection.
        .addRoute("0.0.0.0", 0)
        .addRoute("::", 0)
        .addDnsServer("10.0.0.3")

    private fun resolveProxyAddress(): String {
        val addresses = InetAddress.getAllByName(SOCKS5_HOST)
        return addresses.firstOrNull { it is Inet6Address }?.hostAddress
            ?: addresses.firstOrNull { it is Inet4Address }?.hostAddress
            ?: throw IOException("No se pudo resolver el endpoint SOCKS5 en IPv4 o IPv6.")
    }

    private fun verifySocks5(address: String) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(address, SOCKS5_PORT), 5000)
            socket.soTimeout = 5000
            socket.getOutputStream().write(byteArrayOf(5, 1, 0))
            socket.getOutputStream().flush()

            val response = ByteArray(2)
            var offset = 0
            while (offset < response.size) {
                val count = socket.getInputStream().read(response, offset, response.size - offset)
                if (count < 0) throw IOException("El servidor SOCKS5 cerró el saludo.")
                offset += count
            }
            if (response[0].toInt() != 5 || response[1].toInt() != 0) {
                throw IOException("El servidor SOCKS5 no acepta el modo sin autenticación.")
            }
        }
    }

    private fun downloadThreatFeed(): Set<String> {
        val connection = URL(THREAT_FEED_URL).openConnection() as HttpURLConnection
        connection.connectTimeout = 15000
        connection.readTimeout = 15000
        connection.useCaches = false

        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                throw IOException("El feed de amenazas devolvió HTTP ${connection.responseCode}.")
            }
            return connection.inputStream.bufferedReader().useLines { lines ->
                lines.asSequence()
                    .map { it.substringBefore('#').trim() }
                    .filter(::isIpAddress)
                    .take(MAX_BLOCKED_IPS)
                    .toCollection(HashSet())
            }.also {
                if (it.isEmpty()) throw IOException("El feed no contiene direcciones IP válidas.")
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun isIpv4Address(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            val octet = part.toIntOrNull()
            octet != null && octet in 0..255 && octet.toString() == part
        }
    }

    private fun isIpAddress(value: String): Boolean {
        if (isIpv4Address(value)) return true
        if (!value.contains(':')) return false
        return try {
            InetAddress.getByName(value) is Inet6Address
        } catch (_: IOException) {
            false
        }
    }

    private fun replaceBlockedIps(updated: Set<String>) {
        synchronized(blockedIps) {
            blockedIps.clear()
            blockedIps.addAll(updated)
        }
    }

    private fun blockedIpSnapshot(): Array<String> = synchronized(blockedIps) {
        blockedIps.toTypedArray()
    }

    private fun scheduleFeedRefresh() {
        if (feedRefreshScheduled) return
        feedRefreshScheduled = true
        feedRefresh.scheduleWithFixedDelay({
            try {
                val updated = downloadThreatFeed()
                replaceBlockedIps(updated)
                TProxyService.TProxySetBlockedIps(blockedIpSnapshot())
            } catch (e: Exception) {
                Log.w("AuraVPN", "No se pudo actualizar el feed; se conserva la lista anterior.", e)
            }
        }, 1, 60, TimeUnit.MINUTES)
    }

    private fun reportState(started: Boolean, message: String) {
        sendBroadcast(
            android.content.Intent(ACTION_STATE)
                .setPackage(packageName)
                .putExtra("started", started)
                .putExtra("message", message),
        )
    }

    private fun scheduleNotificationUpdate() {
        if (notificationUpdatePending) return
        notificationUpdatePending = true
        notificationHandler.postDelayed({
            notificationUpdatePending = false
            if (tunnelStarted) {
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, createNotification(currentDnsSummary()))
            }
        }, 500)
    }

    private fun currentDnsSummary(): String = synchronized(dnsMetricsLock) {
        if (panicIsolationActive) {
            "AISLAMIENTO ACTIVO · forwarding detenido"
        } else if (auditedDnsRequests == 0L) {
            "Túnel activo · esperando eventos DNS"
        } else {
            val domain = lastDnsDomain.take(52)
            "DNS $auditedDnsRequests · bloqueados $blockedDnsRequests · " +
                "$domain $lastDnsAction"
        }
    }

    private fun updateForegroundNotification() {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, createNotification(currentDnsSummary()))
    }

    private fun createNotification(
        contentText: String = NOTIFICATION_TEXT,
    ): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            .setContentTitle("🛡️ Aura Centinela Activo")
            .setContentText(NOTIFICATION_TEXT)
            .setSubText(contentText.takeIf { it != NOTIFICATION_TEXT })
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(NOTIFICATION_CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL,
                    NOTIFICATION_CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }
}
