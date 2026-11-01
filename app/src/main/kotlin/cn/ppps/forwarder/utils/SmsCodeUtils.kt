package cn.ppps.forwarder.utils

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import cn.ppps.forwarder.utils.Log

/**
 * 验证码提取与剪贴板复制工具。
 *
 * 提取策略（兼顾中英文短信）：
 * 1. 优先匹配"验证码/动态码/code/otp"等关键词，取其附近的数字串；
 * 2. 兜底：取正文中独立出现的 4~8 位数字串（避免命中长号码/时间戳）。
 */
object SmsCodeUtils {

    private const val TAG = "SmsCodeUtils"

    // 关键词（中英文常见表述）
    private val KEYWORD_REGEX = Regex(
        "(验证码|动态码|校验码|校驗碼|效验码|动态密码|动态密碼|提取码|激活码|激活碼|code|otp|verification|pin|password)",
        RegexOption.IGNORECASE
    )

    // 4~8 位纯数字（最常见的验证码形态）
    private val DIGIT_CODE = Regex("\\d{4,8}")

    // 6~10 位字母数字混合（个别服务商使用，如 ABC123）
    private val ALNUM_CODE = Regex("[A-Za-z0-9]{6,10}")

    /**
     * 从短信文本中提取验证码。提取不到返回 null。
     */
    fun extractSmsCode(text: String?): String? {
        if (text.isNullOrBlank()) return null

        // 1) 关键词附近提取
        val keywordMatch = KEYWORD_REGEX.find(text)
        if (keywordMatch != null) {
            val matched = keywordMatch.value
            Log.d(TAG, "matched keyword: $matched")
            // 关键词之后的窗口（最多 20 个字符）
            val after = text.substring(keywordMatch.range.last + 1).take(20)
            DIGIT_CODE.find(after)?.value?.let { return it }
            ALNUM_CODE.find(after)?.value?.let { return it }
            // 关键词之前窗口（如 "123456 is your code"）
            val before = text.substring(0, keywordMatch.range.first).takeLast(20)
            DIGIT_CODE.find(before)?.value?.let { return it }
            ALNUM_CODE.find(before)?.value?.let { return it }
        }

        // 2) 兜底：独立出现的 4~8 位数字串（前后都不是数字，避免命中长号码）
        DIGIT_CODE.findAll(text).forEach { m ->
            val s = m.range.first
            val e = m.range.last
            val prev = if (s > 0) text[s - 1] else ' '
            val next = if (e + 1 < text.length) text[e + 1] else ' '
            if (!prev.isDigit() && !next.isDigit()) {
                return m.value
            }
        }

        return null
    }

    /**
     * 从短信文本提取验证码并复制到系统剪贴板。
     * 提取到并复制成功返回 true，否则返回 false。
     */
    fun copySmsCodeToClipboard(context: Context, text: String?): Boolean {
        val code = extractSmsCode(text) ?: return false
        return try {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            if (cm == null) {
                Log.e(TAG, "ClipboardManager unavailable")
                return false
            }
            cm.setPrimaryClip(ClipData.newPlainText("sms_code", code))
            Log.i(TAG, "verification code copied to clipboard")
            true
        } catch (e: Exception) {
            Log.e(TAG, "copy to clipboard failed: ${e.message}")
            false
        }
    }
}
