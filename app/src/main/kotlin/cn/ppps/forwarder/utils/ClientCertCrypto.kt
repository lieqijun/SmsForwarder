package cn.ppps.forwarder.utils

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 客户端证书(mTLS)的本地加密存储。
 *
 * 采用 Android Keystore 中的 AES 密钥对证书库(BKS)做静态加密，
 * 用户导入时输入的 PKCS#12 密码仅用于临时解密，**绝不持久化**；
 * 运行时喂给 xhttp2 的 BKS 密码由本 Keystore 密钥确定性派生，同样不落盘。
 * 因此即使数据库/配置被导出，证书与密码都无法在其它设备还原（密钥绑定在本机 Keystore）。
 */
object ClientCertCrypto {

    private const val KEY_ALIAS = "smsf_client_cert_aes"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_LEN = 128
    // 用于确定性派生 BKS 密码的固定 IV：仅对一个常量做加密，不加密可变明文，可固定
    private val FIXED_IV = ByteArray(GCM_IV_LEN)

    private fun getKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEY_ALIAS, null)
        if (entry is KeyStore.SecretKeyEntry) {
            return entry.secretKey
        }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                // 允许固定 IV，用于确定性派生 BKS 密码（真实数据加密仍使用随机 IV）
                .setRandomizedEncryptionRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    /** 加密（GCM，随机 IV 前置） */
    @Throws(Exception::class)
    fun encrypt(plain: ByteArray): ByteArray {
        val key = getKey()
        val iv = ByteArray(GCM_IV_LEN).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LEN, iv))
        val out = ByteArrayOutputStream()
        out.write(iv)
        out.write(cipher.doFinal(plain))
        return out.toByteArray()
    }

    /** 解密 */
    @Throws(Exception::class)
    fun decrypt(data: ByteArray): ByteArray {
        val key = getKey()
        val iv = data.copyOfRange(0, GCM_IV_LEN)
        val ct = data.copyOfRange(GCM_IV_LEN, data.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LEN, iv))
        return cipher.doFinal(ct)
    }

    /**
     * 确定性派生 BKS 密钥库密码：仅本设备可用，不落盘。
     * 发送时用于解锁存盘的 BKS，再喂给 xhttp2 的
     * [com.xuexiang.xhttp2.request.BaseRequest.certificates]。
     */
    @Throws(Exception::class)
    fun deriveBksPassword(seed: String = "smsf-bks-v1"): String {
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LEN, FIXED_IV))
        return Base64.encodeToString(cipher.doFinal(seed.toByteArray()), Base64.NO_WRAP)
    }
}
