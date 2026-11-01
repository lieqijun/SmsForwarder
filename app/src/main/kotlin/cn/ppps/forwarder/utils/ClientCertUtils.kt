package cn.ppps.forwarder.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security

/**
 * 客户端证书(mTLS)工具。
 *
 * 导入流程（在 [cn.ppps.forwarder.fragment.senders.WebhookFragment] 中调用）：
 * 1. 用用户输入的 PKCS#12 密码临时解密证书（密码不持久化）；
 * 2. 将私钥 + 证书链重新封装为 BKS 密钥库（密码由 [ClientCertCrypto.deriveBksPassword] 派生）；
 * 3. 用 Android Keystore 的 AES 密钥加密后存盘（见 [ClientCertCrypto]）。
 *
 * 发送流程（在 [cn.ppps.forwarder.utils.sender.WebhookUtils] 中调用）：
 * 解密存盘的 BKS 字节，连同派生密码一起交给 xhttp2 的
 * [com.xuexiang.xhttp2.request.BaseRequest.certificates]，完成 TLS 握手时出示客户端证书。
 */
object ClientCertUtils {

    /**
     * 将内存中的 PKCS#12(.p12) 字节转换为 BKS 格式密钥库字节。
     *
     * @param p12Bytes    PKCS#12 文件原始字节
     * @param p12Password PKCS#12 密码（导入时由用户输入，仅临时使用）
     * @param bksPassword BKS 密钥库密码（由 [ClientCertCrypto.deriveBksPassword] 派生，不落盘）
     * @return 可直接传给 xhttp2 [com.xuexiang.xhttp2.request.BaseRequest.certificates] 的 BKS 字节
     */
    @Throws(Exception::class)
    fun p12BytesToBksBytes(p12Bytes: ByteArray, p12Password: String, bksPassword: String): ByteArray {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val p12 = KeyStore.getInstance("PKCS12")
        p12.load(ByteArrayInputStream(p12Bytes), p12Password.toCharArray())

        val alias = p12.aliases().toList().first { p12.isKeyEntry(it) }
        val privateKey = p12.getKey(alias, p12Password.toCharArray()) as PrivateKey
        val chain = p12.getCertificateChain(alias)
            ?: arrayOf(p12.getCertificate(alias))

        val bks = KeyStore.getInstance("BKS", BouncyCastleProvider())
        bks.load(null, null)
        bks.setKeyEntry("client", privateKey, bksPassword.toCharArray(), chain)

        val out = ByteArrayOutputStream()
        bks.store(out, bksPassword.toCharArray())
        return out.toByteArray()
    }

    /**
     * 校验 PKCS#12 能否用给定密码打开（导入时调用，不保存密码）。
     */
    @Throws(Exception::class)
    fun verifyP12(p12Bytes: ByteArray, p12Password: String) {
        KeyStore.getInstance("PKCS12").apply {
            load(ByteArrayInputStream(p12Bytes), p12Password.toCharArray())
        }
    }

    /**
     * 解析服务端 CA 证书(X.509，PEM/DER 均可)为输入流：
     * 以 "/" 开头视为文件路径，否则视为 Base64 编码。
     */
    @Throws(Exception::class)
    fun certInputStream(cert: String): InputStream {
        return toInputStream(cert)
    }

    private fun toInputStream(content: String): InputStream {
        return if (content.startsWith("/")) {
            FileInputStream(content)
        } else {
            ByteArrayInputStream(Base64.decode(content))
        }
    }
}
