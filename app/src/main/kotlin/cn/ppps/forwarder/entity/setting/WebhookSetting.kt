package cn.ppps.forwarder.entity.setting

import cn.ppps.forwarder.R
import java.io.Serializable
import java.net.Proxy

data class WebhookSetting(
    val method: String = "POST",
    var webServer: String = "",
    val secret: String = "",
    val response: String = "",
    val webParams: String = "",
    val headers: Map<String, String> = mapOf(),
    val proxyType: Proxy.Type = Proxy.Type.DIRECT,
    val proxyHost: String = "",
    val proxyPort: String = "",
    val proxyAuthenticator: Boolean = false,
    val proxyUsername: String = "",
    val proxyPassword: String = "",
    //客户端证书(mTLS/双向认证)：PKCS#12(.p12)证书内容，以 "/" 开头为文件路径，否则为 Base64
    val clientCert: String = "",
    val clientCertPassword: String = "",
    //服务端CA证书(可选)：用于验证服务端身份；留空则信任所有证书(沿用历史 ignoreHttpsCert 行为)
    val serverCaCert: String = "",
) : Serializable {
    fun getMethodCheckId(): Int {
        return when (method) {
            "POST" -> R.id.rb_method_post
            "PUT" -> R.id.rb_method_put
            "PATCH" -> R.id.rb_method_patch
            else -> R.id.rb_method_get
        }
    }

    fun getProxyTypeCheckId(): Int {
        return when (proxyType) {
            Proxy.Type.HTTP -> R.id.rb_proxyHttp
            Proxy.Type.SOCKS -> R.id.rb_proxySocks
            else -> R.id.rb_proxyNone
        }
    }
}
