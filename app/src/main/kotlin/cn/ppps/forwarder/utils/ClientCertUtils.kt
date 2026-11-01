package cn.ppps.forwarder.utils

import cn.ppps.forwarder.utils.Base64
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
 * xhttp2 的 [com.xuexiang.xhttp2.request.BaseRequest.certificates] 双向认证方法
 * 内部以 **BKS** 格式加载客户端密钥库([com.xuexiang.xhttp2.https.HttpsUtils.prepareKeyManager])，
 * 而用户通常持有 PKCS#12(.p12/.pfx)。因此这里在内存中把 PKCS#12 转换为 BKS，
 * 使 Webhook/通用 HTTP 发送方能直接上传 .p12 完成双向认证(TLS 握手阶段出示客户端证书)。
 */
object ClientCertUtils {

    /**
     * 将 PKCS#12(.p12/.pfx) 转换为 BKS 格式的内存输入流。
     *
     * @param clientCert 证书内容：以 "/" 开头视为文件路径，否则视为 Base64 编码
     * @param password   p12 文件密码
     * @return 可直接传给 [com.xuexiang.xhttp2.request.BaseRequest.certificates] 的 BKS 输入流
     */
    @Throws(Exception::class)
    fun p12ToBksInputStream(clientCert: String, password: String): InputStream {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val p12Stream = toInputStream(clientCert)
        val p12 = KeyStore.getInstance("PKCS12")
        p12.load(p12Stream, password.toCharArray())

        val alias = p12.aliases().toList().first { p12.isKeyEntry(it) }
        val privateKey = p12.getKey(alias, password.toCharArray()) as PrivateKey
        val chain = p12.getCertificateChain(alias)
            ?: arrayOf(p12.getCertificate(alias))

        val bks = KeyStore.getInstance("BKS", BouncyCastleProvider())
        bks.load(null, null)
        bks.setKeyEntry("client", privateKey, password.toCharArray(), chain)

        val out = ByteArrayOutputStream()
        bks.store(out, password.toCharArray())
        return ByteArrayInputStream(out.toByteArray())
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
