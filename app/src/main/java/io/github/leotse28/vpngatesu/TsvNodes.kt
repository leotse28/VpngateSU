package io.github.leotse28.vpngatesu

/**
 * 6-column TSV node export/import — the same format as the desktop
 * client v3.16 (`export_nodes_text` / `parse_import_line` in
 * vpngate-gui.rs):
 *
 *   host:port \t country \t operator \t sessions \t speed(Mbps) \t probe_ms
 *
 * Rules mirrored from the desktop client:
 * - No header line; the first field stays a plain `host:port`, so the
 *   text is still usable as a bare host list.
 * - Country/operator are sanitised (tab / CR / LF become a space) so
 *   a stray tab can never break the line format.
 * - Sessions/speed are empty when 0 (unknown); probe_ms is empty when
 *   never probed. Never a literal placeholder word.
 * - Import accepts the old 5-column form and bare `host:port` lines;
 *   `#` comment lines and blank lines are skipped; a line that is not
 *   a `host[:port]` is counted as malformed, never fatal.
 * - A duplicate host is skipped WHOLE — including its probe latency.
 *   An imported stale value must not overwrite the existing row.
 * - A bare VPNGate label with no dot gains `.opengw.net`
 *   (`complete_ddns_host` in the core).
 *
 * UI wiring (SAF file pick / share) is Phase B; the codec lands in
 * Phase A so the format is pinned — and JVM-tested — before the UI.
 */

/** One parsed import line (probe latency is in-memory only, like the desktop). */
data class TsvNodeRow(
    val host: String,
    val port: Int?,
    val country: String,
    val isp: String,
    val sessions: Long,
    val speedMbps: Long,
    val probeMs: Long?,
) {
    val hostPort: String get() = if (port != null) "$host:$port" else host
}

data class TsvImportResult(
    val rows: List<TsvNodeRow>,
    val malformed: Int,
    val duplicates: Int,
)

/** A bare VPNGate label with no dot is a DDNS hostname. */
fun completeDdnsHost(host: String): String =
    if ('.' in host) host else "$host.opengw.net"

private fun sanitizeField(s: String): String =
    s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')

/** Export nodes in display order (same layout as the desktop client). */
fun exportTsv(nodes: List<NodeDto>, probeMs: Map<String, Long?> = emptyMap()): String =
    nodes.joinToString("\n") { n ->
        val hostPort = if (n.port != null) "${completeDdnsHost(n.host)}:${n.port}" else completeDdnsHost(n.host)
        val sessions = if (n.sessions == 0L) "" else n.sessions.toString()
        val speed = if (n.speed_mbps == 0L) "" else n.speed_mbps.toString()
        val latency = (probeMs[completeDdnsHost(n.host)] ?: probeMs[n.host])?.toString() ?: ""
        listOf(hostPort, sanitizeField(n.country), sanitizeField(n.isp), sessions, speed, latency)
            .joinToString("\t")
    }

/** Parse import text (clipboard or file). Never throws on bad input. */
fun parseTsv(text: String): TsvImportResult {
    val seen = HashSet<String>()
    val rows = ArrayList<TsvNodeRow>()
    var malformed = 0
    var duplicates = 0
    for (raw in text.lines()) {
        val line = raw.trim()
        if (line.isEmpty() || line.startsWith("#")) continue
        val cols = raw.split("\t")
        val hostPort = cols[0].trim()
        if (hostPort.isEmpty()) {
            malformed++
            continue
        }
        // host[:port] — a port must be numeric when present.
        val (hostRaw, port) = when (val i = hostPort.lastIndexOf(':')) {
            -1 -> hostPort to null
            else -> {
                val p = hostPort.substring(i + 1).toIntOrNull()
                if (p == null || p !in 1..65535) {
                    malformed++
                    continue
                }
                hostPort.substring(0, i) to p
            }
        }
        if (hostRaw.isEmpty()) {
            malformed++
            continue
        }
        val host = completeDdnsHost(hostRaw)
        if (!seen.add(host)) {
            duplicates++
            continue
        }
        val country = cols.getOrNull(1) ?: ""
        val isp = cols.getOrNull(2) ?: ""
        val sessions = cols.getOrNull(3)?.trim()?.toLongOrNull() ?: 0L
        val speed = cols.getOrNull(4)?.trim()?.toLongOrNull() ?: 0L
        val probeMs = if (cols.size >= 6) cols[5].trim().toLongOrNull() else null
        rows.add(TsvNodeRow(host, port, country, isp, sessions, speed, probeMs))
    }
    return TsvImportResult(rows, malformed, duplicates)
}
