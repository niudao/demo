package com.gemantic.controller.submit;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.Sign;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.symmetric.AES;

import java.nio.charset.StandardCharsets;


public class aes_rsa {

    private static String aesEncrypt(String plainText, String key) {
        AES aes = SecureUtil.aes(key.getBytes());

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = aes.encrypt(data);
        return Base64.encode(encrypt);
    }

    private static String sign(String raw, String privateKey) {
        Sign sign = SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, null);

        byte[] data = raw.getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign.sign(data);
        return Base64.encode(signature);
    }


    private static String rsaEncrypt(String plainText, String publicKey) {
        RSA rsa = SecureUtil.rsa(null, publicKey);

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = rsa.encrypt(data, KeyType.PublicKey);
        return Base64.encode(encrypt);
    }
}