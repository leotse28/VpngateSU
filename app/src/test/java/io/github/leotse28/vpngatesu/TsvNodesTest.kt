package io.github.leotse28.vpngatesu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TsvNodesTest {

    private fun node(
        host: String,
        port: Int? = 443,
        country: String = "日本",
        isp: String = "Softbank",
        sessions: Long = 12,
        speedMbps: Long = 261,
    ) = NodeDto(
        host = host, port = port, country = country, isp = isp,
        sessions = sessions, speed_mbps = speedMbps,
    )

    @Test
    fun `six column export then import round trips`() {
        val nodes = listOf(
            node("public-vpn-123.opengw.net", 443, sessions = 12, speedMbps = 261),
            node("vpn456.opengw.net", 992, country = "韩国", isp = "KT", sessions = 0, speedMbps = 0),
        )
        val probe = mapOf("public-vpn-123.opengw.net" to 87L)
        val text = exportTsv(nodes, probe)
        val result = parseTsv(text)
        assertEquals(0, result.malformed)
        assertEquals(0, result.duplicates)
        assertEquals(2, result.rows.size)
        val first = result.rows[0]
        assertEquals("public-vpn-123.opengw.net", first.host)
        assertEquals(443, first.port)
        assertEquals("日本", first.country)
        assertEquals("Softbank", first.isp)
        assertEquals(12L, first.sessions)
        assertEquals(261L, first.speedMbps)
        assertEquals(87L, first.probeMs)
        // Unprobed + zero stats export as empty fields, import as null/0.
        val second = result.rows[1]
        assertNull(second.probeMs)
        assertEquals(0L, second.sessions)
        assertEquals(0L, second.speedMbps)
    }

    @Test
    fun `five column legacy import has null probe latency`() {
        val result = parseTsv("vpn1.opengw.net:443\t日本\tSoftbank\t5\t100\n")
        assertEquals(1, result.rows.size)
        assertNull(result.rows[0].probeMs)
        assertEquals(5L, result.rows[0].sessions)
        assertEquals(100L, result.rows[0].speedMbps)
    }

    @Test
    fun `bare host line imports with null port`() {
        val result = parseTsv("vpn9.opengw.net:995\n")
        assertEquals(1, result.rows.size)
        assertEquals(995, result.rows[0].port)
        assertEquals("", result.rows[0].country)
    }

    @Test
    fun `comments blank lines and malformed lines are skipped and counted`() {
        val text = "# a comment\n\nvpn1.opengw.net:443\t日本\t\t3\t50\t\n" +
            "not a host line at all:xx\n" +
            ":443\t日本\n"
        val result = parseTsv(text)
        assertEquals(1, result.rows.size)
        assertEquals(2, result.malformed)
        assertEquals(0, result.duplicates)
    }

    @Test
    fun `duplicate host is skipped whole and keeps the first probe latency`() {
        val text = "vpn1.opengw.net:443\t日本\tSoftbank\t3\t50\t111\n" +
            "vpn1.opengw.net:443\t韩国\tKT\t9\t900\t999\n"
        val result = parseTsv(text)
        assertEquals(1, result.rows.size)
        assertEquals(1, result.duplicates)
        assertEquals(111L, result.rows[0].probeMs)
        assertEquals("日本", result.rows[0].country)
    }

    @Test
    fun `bare label gains opengw net on export and import`() {
        val exported = exportTsv(listOf(node("public-vpn-192", 443)))
        assertTrue(exported.startsWith("public-vpn-192.opengw.net:443\t"))
        val parsed = parseTsv("public-vpn-192:443\t日本\t\t\t\t\n")
        assertEquals("public-vpn-192.opengw.net", parsed.rows[0].host)
        assertEquals("public-vpn-192.opengw.net", completeDdnsHost("public-vpn-192"))
        assertEquals("1.2.3.4", completeDdnsHost("1.2.3.4"))
    }

    @Test
    fun `tabs and newlines in country and isp are sanitised on export`() {
        val exported = exportTsv(
            listOf(node("vpn1.opengw.net", 443, country = "日\t本", isp = "Soft\nbank"))
        )
        val cols = exported.split("\t")
        assertEquals(6, cols.size)
        assertEquals("日 本", cols[1])
        assertEquals("Soft bank", cols[2])
    }
}
