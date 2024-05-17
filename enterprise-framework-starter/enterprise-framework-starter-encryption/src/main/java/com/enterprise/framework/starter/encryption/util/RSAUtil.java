package com.enterprise.framework.starter.encryption.util;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class RSAUtil {

    /**
     * 定义加密方式
     */
    private final static String KEY_RSA = "RSA";


    /**
     * 公钥名称
     */
    public static final String PUBLIC_KEY = "PUBLIC_KEY";


    /**
     * 私钥名称
     */
    public static final String PRIVATE_KEY = "PRIVATE_KEY";


    /**
     * 将加密对象进行sha1后进行rsa加密,加签时候需要
     * SHA-1：一种散列函数
     */
    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";


    /**
     * 初始化密钥长度为2048
     * RSA加解密中必须考虑密钥长度、明文长度和密文长度问题
     * 明文长度需要小于密钥长度，而密文长度则等于密钥长度。因此当加密内容长度大于密钥长度时，有效的RSA加解密就需要对内容进行分段。
     * 介于目前只加密AES密钥，所以不考虑实现分段加密，密钥长度设置为2048即可
     */
    private static final Integer KEY_LENGTH = 1 << 11;


    /**
     * 初始化RSA公私钥
     */
    public static Map<String, Key> initRSAKey() throws NoSuchAlgorithmException {
        //获得对象 KeyPairGenerator 参数 RSA 1024个字节
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_RSA);
        keyPairGen.initialize(KEY_LENGTH);
        //通过对象 KeyPairGenerator 获取对象KeyPair
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //通过对象 KeyPair 获取RSA公私钥对象RSAPublicKey RSAPrivateKey
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        //公私钥对象存入map中
        Map<String, Key> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }


    /**
     * RSA私钥签名
     * @param content 待签名数据
     * @param privateKey 私钥
     * @return 签名值
     */
    public static String sign(String content, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PrivateKey priKey = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return new String(Base64.encodeBase64URLSafe(signed), StandardCharsets.UTF_8);
    }


    /**
     * 通过公钥验签
     * @param content 验签内容
     * @param sign  签名
     * @param publicKey 公钥
     * @return 验签结果
     */
    public static boolean verifySign(String content, String sign, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PublicKey pubKey = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.decodeBase64(sign.getBytes(StandardCharsets.UTF_8)));
    }


    /**
     * 从公钥字符串中获取公钥对象
     * @param key Base64的公钥字符串
     * @return 公钥
     * @throws NoSuchAlgorithmException 异常
     */
    public static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.decodeBase64(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_RSA);
        return keyFactory.generatePublic(keySpec);
    }



    /**
     * 从私钥字符串中获取私钥对象
     * @param key Base64的私钥字符串
     * @return 私钥
     * @throws NoSuchAlgorithmException 异常
     */
    public static PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.decodeBase64(key.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_RSA);
        return keyFactory.generatePrivate(keySpec);
    }



    /**
     * 通过公钥加密
     * @param plainText 明文
     * @param publicKey 公钥
     * @return 密文
     */
    public static String encryptByPublicKey(String plainText, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey pubKey = getPublicKey(publicKey);
        Cipher cipher = Cipher.getInstance(KEY_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] enBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeBase64String(enBytes);
    }



    /**
     * 通过私钥解密
     * @param enStr 加密字符串
     * @param privateKey 私钥
     * @return 明文
     */
    public static String decryptByPrivateKey(String enStr, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey priKey = getPrivateKey(privateKey);
        Cipher cipher = Cipher.getInstance(KEY_RSA);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] deBytes = cipher.doFinal(Base64.decodeBase64(enStr));
        return new String(deBytes);
    }


    /**
     * 测试代码
     * @param args 启动参数
     * @throws Exception 抛出的异常
     */
    public static void main(String[] args) throws Exception {
        String encryptionContent = "待加密数据";
        // 第一步，生成一对公私钥
        Map<String, Key> keys = new HashMap<>(2);
        try {
            keys = RSAUtil.initRSAKey();
        } catch (Exception e){
            System.exit(-1);
        }
        // 获得公钥
        Key publicKey = keys.get(PUBLIC_KEY);
        String base64PublicKeyStr = Base64.encodeBase64String(publicKey.getEncoded());
        System.out.println("base64公钥:" + base64PublicKeyStr);
        // 加密
        String encryptionString = RSAUtil.encryptByPublicKey(encryptionContent, base64PublicKeyStr);
        System.out.println("加密后的内容:" + encryptionString);
        // 获得私钥
        Key privateKey = keys.get(PRIVATE_KEY);
        // 私钥Base64编码字符串
        String base64PrivateKeyStr = Base64.encodeBase64String(privateKey.getEncoded());
        System.out.println("base64私钥:" + base64PrivateKeyStr);
        String decryptionString = RSAUtil.decryptByPrivateKey(encryptionString, base64PrivateKeyStr);
        System.out.println("解密后的内容:" + decryptionString);

        // ======================================== 测试对AES密钥进行加密 =======================================
        String aesBase64PublicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyrKXqKuvTLBuILJJnCq2G+mzJHwLMR16cGcZzXtcW8e7OjvQwHmR65FNeBMaekvTbFtsUhTOqScEFGJxTGhZainP9i3eZeMK5SrM/GxgoMKJzn5YF2qQnNtniRClVPLchkIBR0QBMzN5WSwm3GasINZ6rd5EoFnx6u/XzJiT5vitXu3cfxqi43Rj2EML7VnwJPKKvWBSTk5wV2c4GJKrZ/97U6zTUz2pGJ75Rxz5rnxPHG9IC2XmzFm0vdjC6uT0Z6q+n7E242KEt0jNBh3AOXXxbpsnFBM8ht/EkW7yzbWHxKkyYrj5GH2PICP/T+8SvCu43/1nqCdf2/l3JbEtmwIDAQAB";
        String aesBase64PrivateKeyStr = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDKspeoq69MsG4gskmcKrYb6bMkfAsxHXpwZxnNe1xbx7s6O9DAeZHrkU14Exp6S9NsW2xSFM6pJwQUYnFMaFlqKc/2Ld5l4wrlKsz8bGCgwonOflgXapCc22eJEKVU8tyGQgFHRAEzM3lZLCbcZqwg1nqt3kSgWfHq79fMmJPm+K1e7dx/GqLjdGPYQwvtWfAk8oq9YFJOTnBXZzgYkqtn/3tTrNNTPakYnvlHHPmufE8cb0gLZebMWbS92MLq5PRnqr6fsTbjYoS3SM0GHcA5dfFumycUEzyG38SRbvLNtYfEqTJiuPkYfY8gI/9P7xK8K7jf/WeoJ1/b+XclsS2bAgMBAAECggEAVL9w62PE6nKFyQPiBPpSo78FWIbIgyOJEr/4qNIgHnuWy1VBBYiOuwhIdKDAHEvhvNdIpdTvRwf6C6/RIRor8FhFC+/HoZ/Y6VII3K1PhUdxKLXojPnQNtUBJ+yew7K7AyNLt4k2Wzr1TJRKNzJyW1RxfIqG9OhGXm0jM/bDN/kYjCGs+2zOSicOv7cV3OfUZpLVVLHQQ+XzXWtMoM1P8lFEItgl0863VgpZ13rkdGadGOQ9czkuJ/UQBxYdsQi2p+cjjKWaLf6jL4rDPAKwpMR8k12ZUum3bMDeA3/LGsiY0uPT87nnq5YygGWYz19qF/wR4YAXg8+tQd3Vkqmr0QKBgQDufsc3sqSJVxeg3g8UT2e5pZzBUH3xbjo7eDwN8COs22un2mnKPm9pnBYfZ9ksTjTmF7/kA6IttJ94df+hmxD55UwgcCE2CLEUfnm3gGSBpScJJv/++AvrYsvZgOisaX8IBjmY5P+xvu4z8ke88EJtTYhn8/E2/1fEL/mWxTUeKQKBgQDZkzFePdGO8wkgYPJNGl23fRc1y8bpQ1pLDqkraK8dpSpe2PAj+rmby3vIHPndUkYIPdwEixlC7xgLwM6cvxr+2Q2mTn6u/Nx1veWCOiHgeaIvaEHcn/TyLVVufDhLgYFPU0mYR91A+5xcREXNVnN24gwPA14IPmLeEyudcONeIwKBgC7F9GIrCfPZfcvR4Rk1nX0eSsjq9VhFKuyA3x5Iq2Z6PfnUbwz4A7etofUU09XJnLxHih24zLS0CNaCJdlW5RRtcOmntAu51qjTSSHA73Uxo58649foY8YNQTdt/bPamMxFFES1HKSKcoMDkCgw4oY3P3pLsFH98AOM+SElmg5JAoGBANDd7uyrp7r1MPO2XaULBKCbI2bvYtqXX9ziDCCx9DofTpeS5qWDkh8vrnqi5nNDAhvzVn2+EtggsxLFWxM6mm3AbMwUWqUd9X3KeMMVj2PxIHMmQOPNYtYCExtngJtrjXlbWTEo/Avf/3DL0b6XmWytACqBbwm26i6KdLpFnt/FAoGACdYMP34vJeM5e9YD3JAgCWeVbIxARSjtx/LGzKjiC52xjDISuyNRpjLRDB+IH2zyhJoQFSgXC0xaWzWEMI76uDSuF59H5QfUQLGQOg1HdSA79dUWyemhXVIEJajOq1kJr0+0814eSaZDw8NhCOuVhm9Ydd6bJnKw+kQD0nSsYN4=";
        String aesEncryptionString = RSAUtil.encryptByPublicKey("R4MPHr6GyKUofszalEbARQ==", aesBase64PublicKeyStr);
        System.out.println("AES密钥加密后的内容:" + aesEncryptionString);
        String aesDecryptionString = RSAUtil.decryptByPrivateKey(aesEncryptionString, aesBase64PrivateKeyStr);
        System.out.println("AES解密后的内容:" + aesDecryptionString);

        // ======================================== 加解签 =======================================
        String signRsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhtrxCyIk3db6+VohzE9EO+AZm7PgsRVBKLEySFWWKR0VJGTqD9BvuydlD+FKSOL3G+DXBh0iCGILXea1WyvAsHS/+1F9FiSO4Gihg1n5keRGarp69uai12RSbb9ar2lxszvY1ylUi65QbIZRbuqyLHqR4vMXtt4lE4D8c7DtBrFJ5xOuvxbF0YSKsnTs9thy7PiFuUxdrjKla2gSv1p5pq+sqPU1+yVakd0BEOutWGOQZmzDz2fFuLV7SIDR3TGZLE7PVUCbMmQHlHpQKKGWmlFC1hyLA1UmUDT5Me1tS59RHvRC0kIrZKtmpx4+liWDhj8QMvr/oi9RwvynYKgGSQIDAQAB";
        String signRsaPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCG2vELIiTd1vr5WiHMT0Q74Bmbs+CxFUEosTJIVZYpHRUkZOoP0G+7J2UP4UpI4vcb4NcGHSIIYgtd5rVbK8CwdL/7UX0WJI7gaKGDWfmR5EZqunr25qLXZFJtv1qvaXGzO9jXKVSLrlBshlFu6rIsepHi8xe23iUTgPxzsO0GsUnnE66/FsXRhIqydOz22HLs+IW5TF2uMqVraBK/Wnmmr6yo9TX7JVqR3QEQ661YY5BmbMPPZ8W4tXtIgNHdMZksTs9VQJsyZAeUelAooZaaUULWHIsDVSZQNPkx7W1Ln1Ee9ELSQitkq2anHj6WJYOGPxAy+v+iL1HC/KdgqAZJAgMBAAECggEAMAjsszqGRz68RvWD9HKHq4w3ku6PqoQXoZb8gid6RUrGrSAE/30PT2rI5M8q1quBubxs2xClfrbttZToJIGBMVlkyPBNzgVXnzel0FPMQds9+eZSxn+AoZhqhA0VEEZO6bj3lCx0oQyGOSHe/9M5g/5k2KIeYFTggAIB6nOq+ibG9YmyQbODaYE/MGmZg3yC4K6meF4eeFqwH8iZ07zZKnGc9d9Y9gY/jRY9JlVVpn902mljN1iq+jDkS3QEdpBkWoWD5djkzHxeTFtKSj6xwZmAjluSpeKUde7MECyD5bY9CJs3xiWAWLdWJwcojoTb6YsffcPMcnnTW5G0+7hkwQKBgQDShw8nLWBXaEpMO2SqMu93YAs4my9qqP/OAQWLDbyYiV4rOwGysckH6nYvqKBzwwZeGy1nQ228IjSTJMlcaxd9NNXEekzTZHPGQaUs5sskE2ya2VDiUSHEdXD5+wDZgSm9PM1CwHl/GNh0vh6pV3hICLx8I+zPV3/4W4glXMYbswKBgQCj+6VX5NGSaeDWkrCzRM8erH5Uledbs1UjoIHVHO048PvMcgcAggsyruIOVJ1ir/p2Q+W54oZh0HOWlueJVRjvzk5sHMkzp6zCXk7V/i+gUceuZLY90seI462w+DCctwwYMeW5V9LHVkR7ULntyox7YE5d6zmXZRxsS4BB/+AoEwKBgAWCWUgqLNI8vWz/ROQbTx7tmX2Sugvtfjwy1KVN57iKJ7ez5Jh7hIo7fXpDzGcbHGiMB4UjQ5TfxEZxeP99IfE517o7hRUnFMyEXUEujPRVucrXkwFJJDwS4rD3+461jZURKUHs7YEA8nEjpIPD8TbZW61X91N5s7SZGJf5tIl3AoGAZ+bJ1BAq7d9iU/LsPRprNd9LyGKXDlZpqsJHoXXLpVmj4d2aLCs51ypSF4xrkJ06UHci9w3d4dpHcvI40J53x3Jr5Dq1DaK/ZwSEZTjCio1mvUwY4MFOJqFEa65GdvXQlv/+s9o+toklqRD0TgQZ0Q6rePzTJ+csBD4ujSMIr7sCgYEAvC3bNwOKHyXAzXhSueQBuP95VUhIhpMjWDli8uqPvd+lJS2PQovDpwir5Ttq0bFJpAy+19zXXu9XWHpuCWEYxg/ALYnAnKdxZHckJdeHUp4N4sr+MC8svxaV/63y4l4R+32Yqclm/mUqcMD3Bv7P/uOAdSmuYEHdl7ZiMldW1J4=";
        SortedMap<String, Object> sortedMap = new TreeMap<>();
        sortedMap.put("id", "2074");
        sortedMap.put("num", "1");
        sortedMap.put("itemId", "0");
        sortedMap.put("address_id", 589);
        sortedMap.put("integral", 18);
        sortedMap.put("user_notes", "{}");
        sortedMap.put("user_money", 0);
        sortedMap.put("is_cod", 0);
        sortedMap.put("vip_cut_fee", 0.2);
        sortedMap.put("prom_type", 0);
        String signContent = sortedMap.toString();
        System.out.println("加签数据:" + signContent);
        System.out.println("私钥签名======公钥验证");
        String sign = RSAUtil.sign(signContent, signRsaPrivateKey);
        System.out.println("签名：\n\r" + sign);
        boolean flag = RSAUtil.verifySign(signContent, sign, signRsaPublicKey);
        System.out.println("验签结果：\n\r" + flag);
    }

}
