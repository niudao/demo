<?php

/**
 * [AesSecurity aes加密，支持PHP7+]
 * 算法模式：ECB
 * 密钥长度：128
 * 补码方式：PKCS7Padding
 * 解密串编码方式：base64/十六进制
 */
class AesPhp7
{
    /**
     * [encrypt aes加密]
     * @param    [type]                   $input [要加密的数据]
     * @param    [type]                   $key   [加密key]
     * @return   [type]                          [加密后的数据]
     */
    public static function encrypt($input, $key)
    {
        $key  = self::_sha1prng($key);
        $iv   = '';
        $data = openssl_encrypt($input, 'AES-128-ECB', $key, OPENSSL_RAW_DATA, $iv);
        $data = base64_encode($data);
        return $data;
    }

    /**
     * [decrypt aes解密]
     * @param    [type]                   $sStr [要解密的数据]
     * @param    [type]                   $sKey [加密key]
     * @return   [type]                         [解密后的数据]
     */
    public static function decrypt($sStr, $sKey)
    {
        $sKey      = self::_sha1prng($sKey);
        $iv        = '';
        $decrypted = openssl_decrypt(base64_decode($sStr), 'AES-128-ECB', $sKey, OPENSSL_RAW_DATA, $iv);
        return $decrypted;
    }

    /**
     * SHA1PRNG算法
     * @param  [type] $key [description]
     * @return [type]      [description]
     */
    private static function _sha1prng($key)
    {
        return substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
    }

    /**
     *
     * 产生随机字符串，不长于32位
     * @param int $length
     * @return 产生的随机字符串
     */
    public function getNonceStr($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str   = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

}

/**
 * [Aes aes加密，支持PHP5+]
 * 算法模式：ECB
 * 密钥长度：128
 * 补码方式：PKCS5Padding/PKCS7Padding
 * 解密串编码方式：base64/十六进制
 */
class AesPhp5
{

    public static function encrypt($plain, $key)
    {
        if (trim($key) == '') {
            return false;
        }
        $plain       = strval($plain);
        $block_size  = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
        $padded_data = self::_pkcs5_pad($plain, $block_size);
        $iv_size     = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
        $iv          = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        //$encrypted   = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, self::_sha1prng($key), $padded_data, MCRYPT_MODE_ECB, $iv);
        $encrypted   = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $padded_data, MCRYPT_MODE_ECB, $iv);
        return base64_encode($encrypted);
    }

    public static function decrypt($cipher, $key)
    {
        if (!is_string($cipher) || trim($key) == '') {
            return false;
        }

        if ($decoded = base64_decode($cipher)) {
            $block_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
            $iv         = mcrypt_create_iv($block_size, MCRYPT_RAND);
            //$decrypted  = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, self::_sha1prng($key), $decoded, MCRYPT_MODE_ECB, $iv);
            $decrypted  = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $decoded, MCRYPT_MODE_ECB, $iv);
            return self::_pkcs5_unpad($decrypted);
        }
        return false;
    }

    /**
     *
     * 产生随机字符串，不长于32位
     * @param int $length
     * @return 产生的随机字符串
     */
    public function getNonceStr($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str   = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    private static function _sha1prng($key)
    {
        return substr(openssl_digest(openssl_digest($key, 'sha1', true), 'sha1', true), 0, 16);
    }

    private static function _pkcs5_pad($text, $block_size)
    {
        $pad = $block_size - (strlen($text) % $block_size);
        return $text . str_repeat(chr($pad), $pad);
    }

    private static function _pkcs5_unpad($text)
    {
        $end  = substr($text, -1);
        $last = ord($end);
        $len  = strlen($text) - $last;
        if (substr($text, $len) == str_repeat($end, $last)) {
            return substr($text, 0, $len);
        }
        return false;
    }

    private static function _pkcs7_pad($string, $blocksize = 32)
    {
        $len = strlen($string);
        $pad = $blocksize - ($len % $blocksize);
        $string .= str_repeat(chr($pad), $pad);
        return $string;
    }

    private static function _pkcs7_unpad($string)
    {
        $pad = ord($string{strlen($string) - 1});
        if ($pad > strlen($string)) {
            return false;
        }
        if (strspn($string, chr($pad), strlen($string) - $pad) != $pad) {
            return false;
        }
        return substr($string, 0, -1 * $pad);
    }

}

/**
 * RSA算法类
 * 签名及密文编码：base64字符串/十六进制字符串/二进制字符串流
 * 填充方式: PKCS1Padding（加解密）/NOPadding（解密）
 *
 * Notice:Only accepts a single block. Block size is equal to the RSA key size!
 * 如密钥长度为1024 bit，则加密时数据需小于128字节，加上PKCS1Padding本身的11字节信息，所以明文需小于117字节
 *
 * @author: linvo
 * @version: 1.0.0
 * @date: 2013/1/23
 */
class RSA
{
    public $pubKey = null;
    public $priKey = null;
    /**
     * 自定义错误处理
     */
    private function _error($msg)
    {
        die('RSA Error:' . $msg); //TODO
    }
    /**
     * 构造函数
     *
     * @param string 公钥文件（验签和加密时传入）
     * @param string 私钥文件（签名和解密时传入）
     */
    public function __construct($public_key_file = '', $private_key_file = '')
    {
        if ($public_key_file) {
            $this->_getPublicKey($public_key_file);
        }
        if ($private_key_file) {
            $this->_getPrivateKey($private_key_file);
        }
    }
    /**
     * 生成签名
     *
     * @param string 签名材料
     * @param string 签名编码（base64/hex/bin）
     * @return 签名值
     */
    public function sign($data, $code = 'base64')
    {
        $ret = false;
        if (openssl_sign($data, $ret, $this->priKey,OPENSSL_ALGO_MD5)) {
            $ret = $this->_encode($ret, $code);
        }
        return $ret;
    }
    /**
     * 验证签名
     *
     * @param string 签名材料
     * @param string 签名值
     * @param string 签名编码（base64/hex/bin）
     * @return bool
     */
    public function verify($data, $sign, $code = 'base64')
    {
        $ret  = false;
        $sign = $this->_decode($sign, $code);
        if ($sign !== false) {
            switch (openssl_verify($data, $sign, $this->pubKey,OPENSSL_ALGO_MD5)) {
                case 1:$ret = true;
                    break;
                case 0:
                case -1:
                default:$ret = false;
            }
        }
        return $ret;
    }
    /**
     * 公钥加密
     *
     * @param string 明文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（貌似php有bug，所以目前仅支持OPENSSL_PKCS1_PADDING）
     * @return string 密文
     */
    public function public_encrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING)
    {
        $ret = false;
        if (!$this->_checkPadding($padding, 'en')) {
            $this->_error('padding error');
        }

        if (openssl_public_encrypt($data, $result, $this->pubKey, $padding)) {
            $ret = $this->_encode($result, $code);
        }
        return $ret;
    }

    /**
     * 公钥解密
     *
     * @param string 密文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（OPENSSL_PKCS1_PADDING / OPENSSL_NO_PADDING）
     * @param bool 是否翻转明文（When passing Microsoft CryptoAPI-generated RSA cyphertext, revert the bytes in the block）
     * @return string 明文
     */
    public function public_decrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING, $rev = false)
    {

        $ret  = false;
        $data = $this->_decode($data, $code);
        if (!$this->_checkPadding($padding, 'de')) {
            $this->_error('padding error');
        }

        if ($data !== false) {
            if (openssl_public_decrypt($data, $result, $this->pubKey, $padding)) {
                $ret = $rev ? rtrim(strrev($result), "\0") : '' . $result;
            }
        }
        return $ret;
    }

    /**
     * 私钥加密
     *
     * @param string 明文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（貌似php有bug，所以目前仅支持OPENSSL_PKCS1_PADDING）
     * @return string 密文
     */
    public function private_encrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING)
    {
        $ret = false;
        if (!$this->_checkPadding($padding, 'en')) {
            $this->_error('padding error');
        }

        if (openssl_private_encrypt($data, $result, $this->priKey, $padding)) {
            $ret = $this->_encode($result, $code);
        }
        return $ret;
    }

    /**
     * 私钥解密
     *
     * @param string 密文
     * @param string 密文编码（base64/hex/bin）
     * @param int 填充方式（OPENSSL_PKCS1_PADDING / OPENSSL_NO_PADDING）
     * @param bool 是否翻转明文（When passing Microsoft CryptoAPI-generated RSA cyphertext, revert the bytes in the block）
     * @return string 明文
     */
    public function private_decrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING, $rev = false)
    {

        $ret  = false;
        $data = $this->_decode($data, $code);
        if (!$this->_checkPadding($padding, 'de')) {
            $this->_error('padding error');
        }

        if ($data !== false) {
            if (openssl_private_decrypt($data, $result, $this->priKey, $padding)) {
                $ret = $rev ? rtrim(strrev($result), "\0") : '' . $result;
            }
        }
        return $ret;
    }  

   
    /**
     * 检测填充类型
     * 加密只支持PKCS1_PADDING
     * 解密支持PKCS1_PADDING和NO_PADDING
     *
     * @param int 填充模式
     * @param string 加密en/解密de
     * @return bool
     */
    private function _checkPadding($padding, $type)
    {
        if ($type == 'en') {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        } else {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                case OPENSSL_NO_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        }
        return $ret;
    }
    private function _encode($data, $code)
    {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_encode('' . $data);
                break;
            case 'hex':
                $data = bin2hex($data);
                break;
            case 'bin':
            default:
        }
        return $data;
    }
    private function _decode($data, $code)
    {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_decode($data);
                break;
            case 'hex':
                $data = $this->_hex2bin($data);
                break;
            case 'bin':
            default:
        }
        return $data;
    }
    private function _getPublicKey($file)
    {
        $key_content = $this->_readFile($file);
        if ($key_content) {
            $this->pubKey = openssl_get_publickey($key_content);
        }
    }
    private function _getPrivateKey($file)
    {
        $key_content = $this->_readFile($file);
        if ($key_content) {
            $this->priKey = openssl_get_privatekey($key_content);
        }
    }
    private function _readFile($file)
    {
        $ret = false;
        if (!file_exists($file)) {
            $this->_error("The file {$file} is not exists");
        } else {
            $ret = file_get_contents($file);
        }
        return $ret;
    }
    private function _hex2bin($hex = false)
    {
        $ret = $hex !== false && preg_match('/^[0-9a-fA-F]+$/i', $hex) ? pack("H*", $hex) : false;
        return $ret;
    }
}

