package io.github.leotse28.vpngatesu

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service keeping the local mixed proxy alive while a
 * tunnel is connected. It owns NO connection state — the Rust .so
 * does. Its only jobs: a persistent notification (with a Disconnect
 * button) and keeping the process alive under Android's background
 * limits. No auto-reconnect: if the service is killed, the user
 * reconnects manually (DESIGN.md §4.1).
 */
class ProxyService : Service() {

    companion object {
        const val ACTION_START = "io.github.leotse28.vpngatesu.START"
        const val ACTION_DISCONNECT = "io.github.leotse28.vpngatesu.DISCONNECT"
        const val EXTRA_HOST = "host"
        const val EXTRA_VIP = "vip"
        const val EXTRA_LISTEN = "listen"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "vpngatesu_status"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(
            CHANNEL_ID,
            "VpngateSU 状态",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "隧道连接状态常驻通知" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                // Idempotent: the .so returns an error when not
                // connected, which we ignore here.
                Thread {
                    runCatching { NativeBridge.nativeDisconnect() }
                }.start()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: ""
                val vip = intent.getStringExtra(EXTRA_VIP) ?: ""
                val listen = intent.getStringExtra(EXTRA_LISTEN) ?: ""
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(host, vip, listen),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                )
                return START_NOT_STICKY
            }
            else -> {
                // Restarted with a null intent (killed and recreated):
                // no auto-reconnect by design — stop.
                stopSelf()
                return START_NOT_STICKY
            }
        }
    }

    private fun buildNotification(host: String, vip: String, listen: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("VpngateSU 已连接")
            .setContentText("$host · 出口 $vip · 本地代理 $listen")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("$host\n出口 IP：$vip\n本地代理：$listen\n手机 Wi-Fi 代理填 $listen 即可上网（仅该 Wi-Fi 网络生效）")
            )
            .setContentIntent(openApp)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "断开", disconnect)
            .setOngoing(true)
            .build()
    }
}
