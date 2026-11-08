package io.github.leotse28.vpngatesu

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsJsonTest {

    @Test
    fun `settings encode decode round trips`() {
        val settings = AppSettings(
            frontEnabled = true,
            frontAddr = "127.0.0.1:10808",
            listenAddr = "127.0.0.1",
            localPort = 10818,
            allowLan = true,
            timeoutSecs = 10,
        )
        val json = AppJson.encodeToString(settings)
        val decoded: AppSettings = AppJson.decodeFromString(json)
        assertEquals(settings, decoded)
    }

    @Test
    fun `partial settings json fills defaults`() {
        // Mirrors the Rust merge: fields the UI did not send keep
        // their current (default) value.
        val decoded: AppSettings = AppJson.decodeFromString("""{"frontAddr":"127.0.0.1:10808"}""")
        assertEquals("127.0.0.1:10808", decoded.frontAddr)
        assertFalse(decoded.frontEnabled)
        assertEquals(10818, decoded.localPort)
        assertEquals(10L, decoded.timeoutSecs)
    }

    @Test
    fun `nodes response decodes a rust node list payload`() {
        val payload = """
            {"ok":true,"nodes":[
              {"host":"public-vpn-123.opengw.net","port":443,"country":"日本","country_code":"JP",
               "isp":"Softbank","name":"","score":100,"ping_ms":10,"speed_mbps":261,
               "sessions":12,"ip":"1.2.3.4","backups":[],"port_source":"curated","source":"api"},
              {"host":"vpn999.opengw.net","port":null,"country":"韩国","country_code":"KR",
               "isp":"","name":"","score":0,"ping_ms":0,"speed_mbps":0,
               "sessions":0,"ip":"","backups":[],"port_source":"unknown","source":"api"}
            ],"source":"api","label":"官方 API（2 个节点）"}
        """.trimIndent()
        val resp: NodesResponse = AppJson.decodeFromString(payload)
        assertTrue(resp.ok)
        assertEquals(2, resp.nodes.size)
        assertEquals("public-vpn-123.opengw.net:443", resp.nodes[0].hostPort)
        assertEquals("?", resp.nodes[1].displayPort)
        assertNull(resp.nodes[1].port)
        assertEquals("官方 API（2 个节点）", resp.label)
    }

    @Test
    fun `error response decodes with ok false`() {
        val resp: NodesResponse = AppJson.decodeFromString(
            """{"ok":false,"error":"当前方式刷新节点失败，请用另一种方式刷新：timeout"}"""
        )
        assertFalse(resp.ok)
        assertTrue(resp.error!!.startsWith("当前方式刷新节点失败，请用另一种方式刷新"))
    }
}
