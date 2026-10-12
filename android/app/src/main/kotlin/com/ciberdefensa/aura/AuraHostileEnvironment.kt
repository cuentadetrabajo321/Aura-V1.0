package com.ciberdefensa.aura

import android.content.Context
import android.app.AppOpsManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Log
import android.view.MotionEvent
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

object AuraHostileEnvironment {
    private const val LOG_TAG = "AuraHostileEnvironment"
    private const val EMULATOR_CONFIDENCE_THRESHOLD = 50
    @Volatile
    private var obscuredTouchDetected = false

    private val emulatorFingerprintMarkers = listOf("generic", "unknown")
    private val emulatorModelMarkers = listOf(
        "google_sdk",
        "emulator",
        "sdk_gphone",
    )
    private val emulatorHardwareMarkers = listOf("goldfish", "ranchu", "vbox")

    private val suPaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/system/sbin/su",
        "/system/bin/failsafe/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su",
        "/system/usr/su",
        "/system/sd/xbin/su",
        "/system/xbin/mu",
        "/su/bin/su",
        "/data/adb/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/data/local/su",
    )
    private val magiskPaths = listOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/modules",
    )
    private val kernelSuPaths = listOf(
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ksu/bin/ksud",
    )
    private val rootManagerPackages = listOf(
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "me.weishu.kernelsu",
        "com.rifsx.kernelsu",
    )
    private val instrumentationPackages = listOf(
        "org.frida.frida",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        "com.saurik.substrate",
    )
    private val instrumentationMarkers = listOf(
        "frida",
        "frida-gadget",
        "libfrida",
        "frida-server",
        "gum-js-loop",
        "libxposed",
        "xposed",
        "libsubstrate",
        "substrate",
        "lsposed",
        "edxposed",
        "riru",
    )

    fun inspect(context: Context): Map<String, Any> {
        val indicators = mutableListOf<String>()
        val rootIndicators = mutableListOf<String>()
        val checkErrors = mutableListOf<String>()
        val emulatorReport = inspectEmulator()
        indicators.addAll(emulatorReport.indicators)

        val debuggerConnected = Debug.isDebuggerConnected()
        if (debuggerConnected) indicators.add("debugger_attached")

        collectExistingPaths(suPaths, "su_binary", rootIndicators, checkErrors)
        collectExistingPaths(magiskPaths, "magisk_path", rootIndicators, checkErrors)
        collectExistingPaths(kernelSuPaths, "kernelsu_path", rootIndicators, checkErrors)
        collectInstalledRootPackages(context.packageManager, rootIndicators, checkErrors)
        if (Build.TAGS?.contains("test-keys") == true) {
            rootIndicators.add("build_tags_test_keys")
        }
        if (canExecuteSu(checkErrors)) {
            rootIndicators.add("su_command_available")
        }

        val instrumentation = inspectInstrumentation(context)
        val instrumentationIndicators = instrumentation.indicators
        checkErrors.addAll(instrumentation.errors)
        val overlayReport = inspectScreenOverlay(context)
        checkErrors.addAll(overlayReport.errors)

        indicators.addAll(rootIndicators)
        indicators.addAll(instrumentationIndicators)
        indicators.addAll(overlayReport.indicators)
        val rooted = rootIndicators.any { it != "build_tags_test_keys" }
        val hostile = emulatorReport.isEmulator ||
            indicators.any { !it.startsWith("emulator_") }
        val rootConfidence = rootConfidence(rootIndicators)
        return mapOf(
            "isEmulator" to emulatorReport.isEmulator,
            "emulatorConfidence" to emulatorReport.confidence,
            "emulatorIndicators" to emulatorReport.indicators,
            "isDebuggerConnected" to debuggerConnected,
            "isRooted" to rooted,
            "rootConfidence" to rootConfidence,
            "rootIndicators" to rootIndicators,
            "isInstrumented" to instrumentationIndicators.isNotEmpty(),
            "instrumentationIndicators" to instrumentationIndicators,
            "isScreenOverlayDetected" to overlayReport.isDetected,
            "screenOverlayIndicators" to overlayReport.indicators,
            "auraCanDrawOverlays" to overlayReport.auraCanDrawOverlays,
            "environmentCheckErrors" to checkErrors,
            "isHostile" to hostile,
            "threatLevel" to if (hostile) "CRITICAL" else "SECURE",
            "indicators" to indicators,
            "timestamp" to System.currentTimeMillis(),
        )
    }

    fun detectInstrumentation(context: Context): Boolean =
        inspectInstrumentation(context).indicators.isNotEmpty()

    fun detectEmulator(): Boolean = inspectEmulator().isEmulator

    fun detectScreenOverlay(context: Context): Boolean =
        inspectScreenOverlay(context).isDetected

    /**
     * Reports apps granted overlay permission and obscured touches. Permission alone does not prove
     * that an overlay is currently visible; Android restricts obscuring overlays from touching
     * targets from API 31, so touch flags are only available when an obscured event reaches Aura.
     */
    fun recordObscuredTouch(event: MotionEvent): Boolean {
        val obscured = (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
        val partiallyObscured = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            (event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
        if (obscured || partiallyObscured) {
            obscuredTouchDetected = true
            val reason = if (obscured) "obscured" else "partially_obscured"
            Log.w(LOG_TAG, "Tapjacking signal detected: touch_$reason")
        }
        return obscured || partiallyObscured
    }

    private fun inspectScreenOverlay(context: Context): OverlayReport {
        val indicators = mutableListOf<String>()
        val errors = mutableListOf<String>()
        if (obscuredTouchDetected) {
            indicators.add("obscured_touch_event")
        }

        val auraCanDrawOverlays = try {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                Settings.canDrawOverlays(context)
        } catch (_: SecurityException) {
            errors.add("overlay_own_permission_check_denied")
            false
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val appOpsManager = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            if (appOpsManager == null) {
                errors.add("overlay_app_ops_unavailable")
            } else {
                try {
                    context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                        .asSequence()
                        .filter { it.packageName != context.packageName }
                        .filter { packageInfo ->
                            packageInfo.requestedPermissions
                                ?.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW) == true
                        }
                        .filter { packageInfo ->
                            packageInfo.applicationInfo?.let { applicationInfo ->
                                (applicationInfo.flags and
                                    android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
                            } == true
                        }
                        .forEach { packageInfo ->
                            val packageName = packageInfo.packageName
                            val uid = packageInfo.applicationInfo?.uid ?: return@forEach
                            try {
                                if (appOpsManager.checkOpNoThrow(
                                        AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                                        uid,
                                        packageName,
                                    ) == AppOpsManager.MODE_ALLOWED
                                ) {
                                    indicators.add("overlay_permission_granted:$packageName")
                                }
                            } catch (_: IllegalArgumentException) {
                                errors.add("overlay_app_op_check_failed:$packageName")
                            } catch (_: SecurityException) {
                                errors.add("overlay_app_op_check_denied:$packageName")
                            }
                        }
                } catch (_: SecurityException) {
                    errors.add("overlay_package_query_denied")
                }
            }
        }

        if (indicators.isNotEmpty()) {
            Log.w(LOG_TAG, "Potential screen overlay detected: ${indicators.joinToString()}")
        }
        return OverlayReport(
            isDetected = indicators.isNotEmpty(),
            indicators = indicators,
            auraCanDrawOverlays = auraCanDrawOverlays,
            errors = errors,
        )
    }

    private fun inspectEmulator(): EmulatorReport {
        val indicators = mutableListOf<String>()
        val fingerprint = Build.FINGERPRINT.orEmpty().lowercase()
        val model = Build.MODEL.orEmpty().lowercase()
        val manufacturer = Build.MANUFACTURER.orEmpty().lowercase()
        val hardware = Build.HARDWARE.orEmpty().lowercase()
        val board = Build.BOARD.orEmpty().trim().lowercase()

        if (emulatorFingerprintMarkers.any(fingerprint::contains)) {
            indicators.add("emulator_fingerprint")
        }
        if (emulatorModelMarkers.any(model::contains)) {
            indicators.add("emulator_model")
        }
        if (manufacturer.contains("genymotion")) {
            indicators.add("emulator_manufacturer_genymotion")
        } else if (manufacturer == "unknown") {
            indicators.add("emulator_manufacturer_unknown")
        }
        if (emulatorHardwareMarkers.any(hardware::contains)) {
            indicators.add("emulator_hardware")
        }
        if (board.isEmpty() || board == "unknown") {
            indicators.add("emulator_board")
        }

        val abiList = Build.SUPPORTED_ABIS.orEmpty().map(String::lowercase)
        val hasX86Abi = abiList.any { it == "x86" || it == "x86_64" }
        if (hasX86Abi && indicators.isNotEmpty()) {
            indicators.add("emulator_x86_abi")
        }

        val confidence = indicators.sumOf { indicator ->
            when (indicator) {
                "emulator_fingerprint",
                "emulator_model",
                "emulator_hardware" -> 35
                "emulator_manufacturer_genymotion" -> 50
                "emulator_manufacturer_unknown" -> 20
                "emulator_board" -> 15
                "emulator_x86_abi" -> 10
                else -> 0
            }
        }.coerceAtMost(100)

        indicators.forEach { signal ->
            Log.i(LOG_TAG, "Emulator signal detected: $signal")
        }
        return EmulatorReport(
            isEmulator = confidence >= EMULATOR_CONFIDENCE_THRESHOLD,
            confidence = confidence,
            indicators = indicators,
        )
    }

    private fun inspectInstrumentation(context: Context): InstrumentationReport {
        val indicators = mutableListOf<String>()
        val errors = mutableListOf<String>()

        scanLoadedLibraries(indicators, errors)
        scanInstrumentationPorts(indicators, errors)
        scanInstrumentationPackages(context.packageManager, indicators, errors)
        scanSuspiciousProcesses(indicators, errors)

        return InstrumentationReport(indicators.distinct(), errors.distinct())
    }

    private fun scanLoadedLibraries(
        indicators: MutableList<String>,
        errors: MutableList<String>,
    ) {
        try {
            File("/proc/self/maps").bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val lowerCaseLine = line.lowercase()
                    instrumentationMarkers
                        .filter(lowerCaseLine::contains)
                        .forEach { marker -> indicators.add("library:$marker") }
                }
            }
        } catch (_: IOException) {
            errors.add("instrumentation_maps_unavailable")
        } catch (_: SecurityException) {
            errors.add("instrumentation_maps_access_denied")
        }
    }

    private fun scanInstrumentationPorts(
        indicators: MutableList<String>,
        errors: MutableList<String>,
    ) {
        listOf(27042, 27043).forEach { port ->
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 100)
                }
                indicators.add("frida_port:$port")
            } catch (_: ConnectException) {
                // No service is listening on this port.
            } catch (_: SocketTimeoutException) {
                // A closed or filtered port is not evidence of instrumentation.
            } catch (_: SecurityException) {
                errors.add("instrumentation_port_check_denied:$port")
            } catch (_: IOException) {
                errors.add("instrumentation_port_check_failed:$port")
            }
        }
    }

    private fun scanInstrumentationPackages(
        packageManager: PackageManager,
        indicators: MutableList<String>,
        errors: MutableList<String>,
    ) {
        instrumentationPackages.forEach { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                indicators.add("package:$packageName")
            } catch (_: PackageManager.NameNotFoundException) {
                // The package is not installed.
            } catch (_: SecurityException) {
                errors.add("instrumentation_package_check_denied:$packageName")
            }
        }
    }

    private fun scanSuspiciousProcesses(
        indicators: MutableList<String>,
        errors: MutableList<String>,
    ) {
        val processDirectories = try {
            File("/proc").listFiles()
        } catch (_: SecurityException) {
            errors.add("instrumentation_process_list_access_denied")
            return
        }
        if (processDirectories == null) {
            errors.add("instrumentation_process_list_unavailable")
            return
        }

        var processAccessDenied = false
        processDirectories.asSequence()
            .filter { it.isDirectory && it.name.all(Char::isDigit) }
            .forEach { processDirectory ->
                listOf("cmdline", "comm").forEach { processFile ->
                    try {
                        val processDescription = File(processDirectory, processFile)
                            .bufferedReader()
                            .use { it.readText() }
                            .lowercase()
                        instrumentationMarkers
                            .filter(processDescription::contains)
                            .forEach { marker ->
                                indicators.add("process:$marker")
                            }
                    } catch (_: IOException) {
                        // Processes can exit while /proc is being scanned.
                    } catch (_: SecurityException) {
                        processAccessDenied = true
                    }
                }
            }
        if (processAccessDenied) {
            errors.add("instrumentation_process_access_denied")
        }
    }

    private fun collectExistingPaths(
        paths: List<String>,
        indicatorPrefix: String,
        indicators: MutableList<String>,
        checkErrors: MutableList<String>,
    ) {
        paths.forEach { path ->
            try {
                if (File(path).exists()) {
                    indicators.add("${indicatorPrefix}:$path")
                }
            } catch (exception: SecurityException) {
                checkErrors.add("path_check_failed:$path")
            }
        }
    }

    private fun collectInstalledRootPackages(
        packageManager: PackageManager,
        indicators: MutableList<String>,
        checkErrors: MutableList<String>,
    ) {
        rootManagerPackages.forEach { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                indicators.add("root_manager_package:$packageName")
            } catch (_: PackageManager.NameNotFoundException) {
                // The package is not installed.
            } catch (_: SecurityException) {
                checkErrors.add("package_check_failed:$packageName")
            }
        }
    }

    private fun canExecuteSu(checkErrors: MutableList<String>): Boolean {
        val command = FutureTask {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            try {
                process.outputStream.close()
                val exitCode = process.waitFor()
                val output = process.inputStream.bufferedReader().use { it.readText() }
                exitCode == 0 && Regex("""\buid=0(?:\(|\b)""").containsMatchIn(output)
            } finally {
                process.destroy()
            }
        }
        Thread(command, "aura-su-root-check").apply {
            isDaemon = true
            start()
        }

        return try {
            command.get(2, TimeUnit.SECONDS)
        } catch (_: TimeoutException) {
            command.cancel(true)
            checkErrors.add("su_command_check_timed_out")
            false
        } catch (exception: InterruptedException) {
            command.cancel(true)
            Thread.currentThread().interrupt()
            checkErrors.add("su_command_check_interrupted")
            false
        } catch (exception: ExecutionException) {
            when (exception.cause) {
                is IOException, is SecurityException -> {
                    checkErrors.add("su_command_check_failed")
                    false
                }
                else -> throw exception
            }
        }
    }

    private fun rootConfidence(rootIndicators: List<String>): Int {
        val strongIndicators = rootIndicators.filter {
            it != "build_tags_test_keys"
        }
        if (strongIndicators.any { it == "su_command_available" }) return 100
        if (strongIndicators.isEmpty()) {
            return if (rootIndicators.isEmpty()) 0 else 30
        }

        val baseConfidence = when {
            strongIndicators.any { it.startsWith("magisk_path:") || it.startsWith("kernelsu_path:") } -> 90
            strongIndicators.any { it.startsWith("su_binary:") } -> 85
            else -> 80
        }
        return (baseConfidence + (strongIndicators.size - 1) * 5).coerceAtMost(99)
    }

    private data class InstrumentationReport(
        val indicators: List<String>,
        val errors: List<String>,
    )

    private data class EmulatorReport(
        val isEmulator: Boolean,
        val confidence: Int,
        val indicators: List<String>,
    )

    private data class OverlayReport(
        val isDetected: Boolean,
        val indicators: List<String>,
        val auraCanDrawOverlays: Boolean,
        val errors: List<String>,
    )
}
