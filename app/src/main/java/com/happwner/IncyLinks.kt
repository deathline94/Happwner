package com.happwner

import android.net.Uri
import android.util.Base64

// Handler for INCY deep links (incy://add/<url>, incy://import/<base64>): mirrors INCY's own cg.h.b extraction
object IncyLinks {

    private const val ADD_PREFIX = "incy://add/"
    private const val IMPORT_PREFIX = "incy://import/"
    private const val INCY_SCHEME = "incy://"
    private const val EXTRACT_MAX_DEPTH = 2

    private val SCHEMES = arrayOf(
        "http://", "https://", "vless://", "vmess://", "trojan://",
        "ss://", "hy2://", "hysteria2://", "socks://", "socks5://",
        "wireguard://", "wg://"
    )

    // Is this an incy://add/ or incy://import/ deep link?
    fun isIncyLink(link: String?): Boolean {
        if (link == null) return false
        val t = link.trim()
        return t.regionMatches(0, ADD_PREFIX, 0, ADD_PREFIX.length, ignoreCase = true) ||
            t.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true)
    }

    // Strip incy://add/ or incy://import/ and unwrap (url-decode, then scheme-or-base64) to the inner link
    fun stripIncyPrefix(link: String?): String? {
        if (link == null) return null
        val trimmed = link.trim()
        val tail = when {
            trimmed.regionMatches(0, ADD_PREFIX, 0, ADD_PREFIX.length, ignoreCase = true) ->
                trimmed.substring(ADD_PREFIX.length)
            trimmed.regionMatches(0, IMPORT_PREFIX, 0, IMPORT_PREFIX.length, ignoreCase = true) ->
                trimmed.substring(IMPORT_PREFIX.length)
            else -> return null
        }.trim()
        if (tail.isEmpty()) return null

        val decoded = try { Uri.decode(tail) } catch (_: Throwable) { tail }
        if (decoded.isEmpty()) return null
        if (looksLikeSchemeLink(decoded)) return decoded

        decodeBase64OrNull(decoded.replace("-", "+").replace("_", "/"))?.let { return it }
        decodeBase64OrNull(decoded)?.let { return it }
        return null
    }

    // Extract an incy://add/ or incy://import/ link wrapped in http(s) (up to 2 levels of URL-decoding)
    fun extractEmbeddedIncyLink(raw: String?): String? = extractEmbeddedIncyLink(raw, 0)

    private fun extractEmbeddedIncyLink(raw: String?, depth: Int): String? {
        if (raw == null) return null
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null

        if (trimmed.startsWith(INCY_SCHEME, ignoreCase = true)) return null
        if (!trimmed.startsWith("http://", ignoreCase = true) &&
            !trimmed.startsWith("https://", ignoreCase = true)) return null

        val start = indexOfIncyScheme(trimmed)
        if (start < 0) {
            if (depth < EXTRACT_MAX_DEPTH && trimmed.indexOf("incy%", ignoreCase = true) >= 0) {
                val once = try { Uri.decode(trimmed) } catch (_: Throwable) { null }
                if (once != null && once != trimmed) return extractEmbeddedIncyLink(once, depth + 1)
            }
            return null
        }

        val candidate = carveIncyCandidate(trimmed, start)
        val rawDecoded = try { Uri.decode(candidate) } catch (_: Throwable) { candidate }
        var decoded = (rawDecoded ?: candidate).trim()

        var guard = 0
        while (guard < EXTRACT_MAX_DEPTH && decoded.startsWith("incy%", ignoreCase = true)) {
            val next = try { Uri.decode(decoded) } catch (_: Throwable) { null } ?: break
            val nextTrimmed = next.trim()
            if (nextTrimmed == decoded) break
            decoded = nextTrimmed
            guard++
        }

        if (!isIncyLink(decoded)) return null
        if (decoded == trimmed) return null
        return decoded
    }

    private fun looksLikeSchemeLink(s: String): Boolean {
        for (p in SCHEMES) if (s.startsWith(p, ignoreCase = true)) return true
        return false
    }

    // Pad to a multiple of 4, base64-decode (DEFAULT) and read as UTF-8; null on failure or empty
    private fun decodeBase64OrNull(s: String): String? {
        var t = s
        while (t.length % 4 != 0) t += "="
        return try {
            val str = String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8)
            if (str.isNotEmpty()) str else null
        } catch (_: Throwable) {
            null
        }
    }

    // Locate 'incy' followed by :// or %3a (case-insensitive)
    private fun indexOfIncyScheme(s: String): Int {
        val scheme = "incy"
        val n = s.length
        var i = 0
        while (i < n) {
            if (i + scheme.length <= n && s.regionMatches(i, scheme, 0, scheme.length, ignoreCase = true)) {
                val rest = i + scheme.length
                if (rest + 3 <= n && s[rest] == ':' && s[rest + 1] == '/' && s[rest + 2] == '/') return i
                if (rest + 3 <= n && s[rest] == '%' && s[rest + 1] == '3' &&
                    (s[rest + 2] == 'a' || s[rest + 2] == 'A')) return i
            }
            i++
        }
        return -1
    }

    // Take everything up to the first delimiter
    private fun carveIncyCandidate(s: String, start: Int): String {
        var end = start
        while (end < s.length && !isIncyDelimiter(s[end])) end++
        return s.substring(start, end)
    }

    // Characters that terminate an incy:// link
    private fun isIncyDelimiter(c: Char): Boolean {
        val o = c.code
        if (o < 0x20 || o > 0x7e) return true
        return when (c) {
            ' ', '&', '#', '"', '\'', '`', '<', '>', '\\', '|', '^', '{', '}', '[', ']' -> true
            else -> false
        }
    }
}
