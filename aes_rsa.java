package com.gemantic.controller.submit;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.Sign;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.symmetric.AES;

import java.nio.charset.StandardCharsets;

/**
 * maven引入hutool-crypto的依赖
 */
public class aes_rsa {

    /**
     * aes加密
     *
     * @param plainText 明文
     * @param key       base64编码的对称密钥
     * @return data
     */
    private static String aesEncrypt(String plainText, String key) {
        AES aes = SecureUtil.aes(key.getBytes());

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = aes.encrypt(data);
        return Base64.encode(encrypt);
    }

    /**
     * 签名
     *
     * @param raw        需要加签的数据
     * @param privateKey base64编码的私钥
     * @return sign
     */
    private static String sign(String raw, String privateKey) {
        Sign sign = SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, null);

        byte[] data = raw.getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign.sign(data);
        return Base64.encode(signature);
    }

    /**
     * rsa加密
     *
     * @param plainText 明文
     * @param publicKey base64编码的公钥
     * @return secret
     */
    private static String rsaEncrypt(String plainText, String publicKey) {
        RSA rsa = SecureUtil.rsa(null, publicKey);

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = rsa.encrypt(data, KeyType.PublicKey);
        return Base64.encode(encrypt);
    }
}