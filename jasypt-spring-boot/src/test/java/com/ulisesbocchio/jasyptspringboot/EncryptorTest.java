package com.ulisesbocchio.jasyptspringboot;

import com.ulisesbocchio.jasyptspringboot.configuration.StringEncryptorBuilder;
import com.ulisesbocchio.jasyptspringboot.encryptor.*;
import com.ulisesbocchio.jasyptspringboot.properties.JasyptEncryptorConfigurationProperties;
import com.ulisesbocchio.jasyptspringboot.util.AsymmetricCryptography;
import lombok.SneakyThrows;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.salt.RandomSaltGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EncryptorTest {

    private static String gcmKey = null;
    private SimplePBEByteEncryptor _PBEWITHHMACSHA512ANDAES_256 = null;
    private SimplePBEStringEncryptor stringEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyFileEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyResourceEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyStringEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyFilePemEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyResourcePemEncryptor = null;
    private SimpleAsymmetricStringEncryptor keyStringPemEncryptor = null;
    private SimpleGCMStringEncryptor gcmKeyEncryptor = null;
    private SimpleGCMStringEncryptor gcmKeyLocationEncryptor = null;
    private SimpleGCMStringEncryptor gcmPasswordEncryptor = null;
    private SimpleGCMConfig gcmPasswordEncryptorConfig = null;
    private SimpleGCMConfig gcmPasswordNoSaltEncryptorConfig = null;
    private SimpleGCMStringEncryptor gcmPasswordNoSaltEncryptor = null;
    private PooledStringEncryptor gcmPooledKeyEncryptor = null;

    @BeforeAll
    public static void setupClass() {
//        System.out.println("====== Algorithms ==========");
//        System.out.println(Stream.of(Security.getProviders()).map(EncryptorTest::getProviderDetails).collect(Collectors.joining("\n")));
//        System.out.println("===========================");
//        System.out.println();
//        System.out.println("====== Algorithms ==========");
//        System.out.println(Stream.of(Security.getProviders()).map(EncryptorTest::getProviderDetails).collect(Collectors.joining("\n")));
//        for (Provider provider: Security.getProviders()) {
//            System.out.println(provider.getName());
//            for (String key: provider.stringPropertyNames())
//                System.out.println("\t" + key + "\t" + provider.getProperty(key));
//        }
        System.out.println("===========================");
        gcmKey = SimpleGCMByteEncryptor.generateBase64EncodedSecretKey();
        System.out.println("GCM KEY");
        System.out.println(gcmKey);
    }

    @BeforeEach
    public void setup() {
        setup_PBEWITHHMACSHA512ANDAES_256();
        setup_stringEncryptor();
        setup_keyFileEncryptor();
        setup_keyResourceEncryptor();
        setup_keyStringEncryptor();
        setup_keyFilePemEncryptor();
        setup_keyResourcePemEncryptor();
        setup_keyStringPemEncryptor();
        setup_gcmKeyEncryptor();
        setup_gcmKeyLocationEncryptor();
        setup_gcmPasswordEncryptor();
        setup_gcmPasswordNoSaltEncryptor();
        setup_pooledGcmKeyEncryptor();
    }

    @SneakyThrows
    private void setup_gcmPasswordEncryptor() {
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyPassword("sumbudrule");
        byte[] salt = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        String saltb = Base64.getEncoder().encodeToString(salt);
        System.out.println("SALT base64 " + saltb);
        config.setSecretKeySalt(saltb);
        gcmPasswordEncryptorConfig = config;
        gcmPasswordEncryptor = new SimpleGCMStringEncryptor(config);
    }

    @SneakyThrows
    private void setup_gcmPasswordNoSaltEncryptor() {
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyPassword("sumbudrule");
        gcmPasswordNoSaltEncryptorConfig = config;
        gcmPasswordNoSaltEncryptor = new SimpleGCMStringEncryptor(config);
    }

    private void setup_pooledGcmKeyEncryptor() {
        gcmPooledKeyEncryptor = new PooledStringEncryptor(10, () -> {
            SimpleGCMConfig config = new SimpleGCMConfig();
            config.setSecretKey(gcmKey);
            return new SimpleGCMStringEncryptor(config);
        });
    }

    private void setup_gcmKeyEncryptor() {
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKey(gcmKey);
        gcmKeyEncryptor = new SimpleGCMStringEncryptor(config);
    }

    private void setup_gcmKeyLocationEncryptor() {
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyLocation("classpath:secret_key.b64");
        gcmKeyLocationEncryptor = new SimpleGCMStringEncryptor(config);
    }

    private void setup_keyFileEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        config.setPrivateKeyLocation("classpath:private_key.der");
        config.setPublicKeyLocation("classpath:public_key.der");
        keyFileEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    private void setup_keyResourceEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        config.setPrivateKeyResource(new ClassPathResource("private_key.der"));
        config.setPublicKeyResource(new ClassPathResource("public_key.der"));
        keyResourceEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    @SneakyThrows
    private void setup_keyStringEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        String privateKey = Base64.getEncoder().encodeToString(FileCopyUtils.copyToByteArray(new ClassPathResource("private_key.der").getInputStream()));
        String publicKey = Base64.getEncoder().encodeToString(FileCopyUtils.copyToByteArray(new ClassPathResource("public_key.der").getInputStream()));
        config.setPrivateKey(privateKey);
        config.setPublicKey(publicKey);
        keyStringEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    private void setup_keyFilePemEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        config.setPrivateKeyLocation("classpath:private_key.pem");
        config.setPublicKeyLocation("classpath:public_key.pem");
        config.setPrivateKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        config.setPublicKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        keyFilePemEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    private void setup_keyResourcePemEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        config.setPrivateKeyResource(new ClassPathResource("private_key.pem"));
        config.setPublicKeyResource(new ClassPathResource("public_key.pem"));
        config.setPrivateKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        config.setPublicKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        keyResourcePemEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    @SneakyThrows
    private void setup_keyStringPemEncryptor() {
        SimpleAsymmetricConfig config = new SimpleAsymmetricConfig();
        String privateKey = FileCopyUtils.copyToString(new InputStreamReader(new ClassPathResource("private_key.pem").getInputStream()));
        String publicKey = FileCopyUtils.copyToString(new InputStreamReader(new ClassPathResource("public_key.pem").getInputStream()));

        config.setPrivateKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        config.setPublicKeyFormat(AsymmetricCryptography.KeyFormat.PEM);
        config.setPrivateKey(privateKey);
        config.setPublicKey(publicKey);
        keyStringPemEncryptor = new SimpleAsymmetricStringEncryptor(config);
    }

    private static String getProviderDetails(Provider provider) {
        final String serviceName = "Cipher";
        final String type = "PBE";
        return provider.getName() + "\n\t"
                + provider.keySet().stream()
                .map(k -> ((String) k).toUpperCase())
                .filter(k -> k.startsWith(serviceName.toUpperCase()) && !k.contains(" "))
                .map(k -> k.substring(serviceName.length() + 1))
                .filter(k -> k.startsWith(type))
                .collect(Collectors.joining("\n\t"));
    }

    private void setup_stringEncryptor() {
        stringEncryptor = new SimplePBEStringEncryptor(_PBEWITHHMACSHA512ANDAES_256);
    }

    @SneakyThrows
    private void setup_PBEWITHHMACSHA512ANDAES_256() {
        SimplePBEByteEncryptor encryptor = new SimplePBEByteEncryptor();
        encryptor.setPassword("some password loco");
        encryptor.setSaltGenerator(new RandomSaltGenerator());
        encryptor.setIterations(1000);
        encryptor.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        _PBEWITHHMACSHA512ANDAES_256 = encryptor;
    }

    @Test
    public void test_asymmetric_key_file_encryption() {
        final String message = "This is the secret message... BOOHOOO!";
        final String encrypted = keyFileEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyFileEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_asymmetric_key_resource_encryption() {
        final String message = "This is the secret resource message... BOOHOOO!";
        final String encrypted = keyResourceEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyResourceEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_asymmetric_key_string_encryption() {
        final String message = "This is the secret string message... BOOHOOO!";
        final String encrypted = keyStringEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyStringEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_asymmetric_key_file_pem_encryption() {
        final String message = "This is the secret pem message... BOOHOOO!";
        final String encrypted = keyFilePemEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyFilePemEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_asymmetric_key_resource_pem_encryption() {
        final String message = "This is the secret resource pem message... BOOHOOO!";
        final String encrypted = keyResourcePemEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyResourcePemEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_asymmetric_key_string_pem_encryption() {
        final String message = "chupacabras";
        final String encrypted = keyStringPemEncryptor.encrypt(message);
        System.out.println(encrypted);
        final String decrypted = keyStringPemEncryptor.decrypt(encrypted);
        System.out.println(decrypted);
        assertEquals(decrypted, message);
    }

    @Test
    public void test_PBEWITHHMACSHA512ANDAES_256_encryption() {
        final String message = "chupacabras";
        final byte[] messageBytes = message.getBytes(StandardCharsets.US_ASCII);

        final byte[] ciphertext = _PBEWITHHMACSHA512ANDAES_256.encrypt(messageBytes);

        final String decrypted = new String(
                _PBEWITHHMACSHA512ANDAES_256.decrypt(ciphertext),
                StandardCharsets.US_ASCII);

        assertEquals(message, decrypted);
    }

    @Test
    public void test_StringEncrytor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = stringEncryptor.encrypt(message);

        final String decrypted = stringEncryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    public void test_GcmKeyEncryptor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmKeyEncryptor.encrypt(message);

        final String decrypted = gcmKeyEncryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    public void test_GcmKeyLocationEncryptor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmKeyLocationEncryptor.encrypt(message);

        System.out.println(ciphertext);

        final String decrypted = gcmKeyLocationEncryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    public void test_GcmPasswordEncryptor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmPasswordEncryptor.encrypt(message);

        System.out.println(ciphertext);

        final String decrypted = gcmPasswordEncryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    @SneakyThrows
    public void test_GcmPasswordEncryptor_encryption2() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmPasswordEncryptor.encrypt(message);

        SimpleGCMStringEncryptor encryptor = new SimpleGCMStringEncryptor(gcmPasswordEncryptorConfig);

        final String decrypted = encryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    public void test_GcmPasswordNoSaltEncryptor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        // a password without a salt must not fall back to a predictable all-zero salt
        assertNull(gcmPasswordNoSaltEncryptorConfig.getSecretKeySaltGenerator());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> gcmPasswordNoSaltEncryptor.encrypt(message));

        assertEquals("Secret key Salt must be provided with password", e.getMessage());
    }

    @Test
    @SneakyThrows
    public void test_GcmPasswordNoSaltEncryptor_encryption2() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmPasswordEncryptor.encrypt(message);

        SimpleGCMStringEncryptor encryptor = new SimpleGCMStringEncryptor(gcmPasswordNoSaltEncryptorConfig);

        assertThrows(IllegalArgumentException.class, () -> encryptor.decrypt(ciphertext));
    }

    @Test
    public void test_GcmByteEncryptor_passwordWithoutSalt_isRejected() {
        final byte[] message = "chupacabras".getBytes(StandardCharsets.UTF_8);
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyPassword("sumbudrule");
        SimpleGCMByteEncryptor encryptor = new SimpleGCMByteEncryptor(config);

        assertNull(config.getSecretKeySaltGenerator());
        assertThrows(IllegalArgumentException.class, () -> encryptor.encrypt(message));
        assertThrows(IllegalArgumentException.class, () -> encryptor.decrypt(new byte[SimpleGCMByteEncryptor.GCM_IV_LENGTH + 16]));
    }

    @Test
    @SneakyThrows
    public void test_GcmByteEncryptor_passwordWithSalt_encryption() {
        final byte[] message = "chupacabras".getBytes(StandardCharsets.UTF_8);
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyPassword("sumbudrule");
        config.setSecretKeySalt(randomBase64Salt());

        final byte[] ciphertext = new SimpleGCMByteEncryptor(config).encrypt(message);

        assertArrayEquals(message, new SimpleGCMByteEncryptor(config).decrypt(ciphertext));
    }

    @Test
    @SneakyThrows
    public void test_GcmByteEncryptor_passwordWithSaltGenerator_encryption() {
        final byte[] message = "chupacabras".getBytes(StandardCharsets.UTF_8);
        SimpleGCMConfig config = new SimpleGCMConfig();
        config.setSecretKeyPassword("sumbudrule");
        FixedBase64ByteArraySaltGenerator saltGenerator = new FixedBase64ByteArraySaltGenerator(randomBase64Salt());
        config.setSaltGenerator(saltGenerator);

        assertSame(saltGenerator, config.getSecretKeySaltGenerator());

        final byte[] ciphertext = new SimpleGCMByteEncryptor(config).encrypt(message);

        assertArrayEquals(message, new SimpleGCMByteEncryptor(config).decrypt(ciphertext));
    }

    @Test
    @SneakyThrows
    public void test_GcmPassword_differentSalts_deriveDifferentKeys() {
        final byte[] message = "chupacabras".getBytes(StandardCharsets.UTF_8);
        SimpleGCMConfig config1 = new SimpleGCMConfig();
        config1.setSecretKeyPassword("sumbudrule");
        config1.setSecretKeySalt(randomBase64Salt());
        SimpleGCMConfig config2 = new SimpleGCMConfig();
        config2.setSecretKeyPassword("sumbudrule");
        config2.setSecretKeySalt(randomBase64Salt());

        SecretKey key1 = SimpleGCMByteEncryptor.getAESKeyFromPassword(config1.getSecretKeyPasswordChars(), config1.getSecretKeySaltGenerator(), config1.getSecretKeyIterations(), config1.getSecretKeyAlgorithm());
        SecretKey key2 = SimpleGCMByteEncryptor.getAESKeyFromPassword(config2.getSecretKeyPasswordChars(), config2.getSecretKeySaltGenerator(), config2.getSecretKeyIterations(), config2.getSecretKeyAlgorithm());

        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));

        final byte[] ciphertext = new SimpleGCMByteEncryptor(config1).encrypt(message);

        assertThrows(AEADBadTagException.class, () -> new SimpleGCMByteEncryptor(config2).decrypt(ciphertext));
    }

    @Test
    public void test_GcmPasswordWithoutSalt_fromConfigProperties_isRejected() {
        final String message = "This is the secret message... BOOHOOO!";
        JasyptEncryptorConfigurationProperties configProps = new JasyptEncryptorConfigurationProperties();
        configProps.setGcmSecretKeyPassword("sumbudrule");

        StringEncryptor noSaltEncryptor = new StringEncryptorBuilder(configProps, "jasypt.encryptor").build();

        assertThrows(IllegalArgumentException.class, () -> noSaltEncryptor.encrypt(message));

        configProps.setGcmSecretKeySalt(randomBase64Salt());

        StringEncryptor saltEncryptor = new StringEncryptorBuilder(configProps, "jasypt.encryptor").build();

        assertEquals(message, saltEncryptor.decrypt(saltEncryptor.encrypt(message)));
    }

    private static String randomBase64Salt() {
        byte[] salt = new byte[SimpleGCMByteEncryptor.AES_KEY_PASSWORD_SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    @Test
    public void test_GcmPooledEncryptor_encryption() {
        final String message = "This is the secret message... BOOHOOO!";

        final String ciphertext = gcmPooledKeyEncryptor.encrypt(message);

        final String decrypted = gcmPooledKeyEncryptor.decrypt(ciphertext);

        assertEquals(message, decrypted);
    }

    @Test
    @SneakyThrows
    public void test_GcmPooledEncryptor_encryption_concurrency() {
        final String message = "This is the secret message... BOOHOOO!";

        ForkJoinPool customThreadPool = new ForkJoinPool(20);
        try {
            List<String> cipherText = customThreadPool.submit(() -> IntStream
                    .range(0, 100)
                    .boxed()
                    .parallel()
                    .map(v -> gcmPooledKeyEncryptor.encrypt(message))
                    .collect(Collectors.toList())).get();
            List<String> decrypted = customThreadPool.submit(() ->
                    cipherText
                            .stream()
                            .parallel()
                            .map(gcmPooledKeyEncryptor::decrypt)
                            .collect(Collectors.toList())
            ).get();
            assertAll(decrypted.stream().map((v -> () -> assertEquals(message, v))));
        } finally {
            customThreadPool.shutdown();
        }
    }
}
