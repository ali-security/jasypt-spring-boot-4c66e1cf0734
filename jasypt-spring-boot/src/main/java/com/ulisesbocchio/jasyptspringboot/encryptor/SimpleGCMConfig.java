package com.ulisesbocchio.jasyptspringboot.encryptor;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import org.jasypt.iv.IvGenerator;
import org.jasypt.salt.SaltGenerator;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Data
@NoArgsConstructor
public class SimpleGCMConfig {
    private ResourceLoader resourceLoader = new DefaultResourceLoader();
    private Resource secretKeyResource;
    private String secretKeyLocation;
    private String secretKey;
    private String secretKeyPassword;
    private String secretKeySalt;
    private String algorithm = "AES/GCM/NoPadding";
    private String secretKeyAlgorithm = "PBKDF2WithHmacSHA256";
    private int secretKeyIterations = 1000;
    private SecretKey actualKey = null;
    private SaltGenerator saltGenerator = null;
    private IvGenerator ivGenerator = null;
    private String ivGeneratorClassName = "org.jasypt.iv.RandomIvGenerator";

    private Resource loadResource(Resource asResource, String asString, String asLocation) {
        return Optional.ofNullable(asResource)
                .orElseGet(() ->
                        Optional.ofNullable(asString)
                                .map(pk -> (Resource) new ByteArrayResource(pk.getBytes(StandardCharsets.UTF_8)))
                                .orElseGet(() ->
                                        Optional.ofNullable(asLocation)
                                                .map(resourceLoader::getResource)
                                                .orElseThrow(() -> new IllegalArgumentException("Unable to load secret key. Either resource, key as string, or resource location must be provided"))));
    }

    public Resource loadSecretKeyResource() {
        return loadResource(secretKeyResource, secretKey, secretKeyLocation);
    }

    public char[] getSecretKeyPasswordChars() {
        return secretKeyPassword.toCharArray();
    }

    /**
     * Salt generator used to derive the secret key from {@code secretKeyPassword}: the explicit {@code saltGenerator}
     * if set, otherwise a fixed generator for the base64 {@code secretKeySalt}. There is no fallback to an all-zero
     * salt; when neither is configured this returns {@code null} and password based key derivation is rejected.
     */
    public SaltGenerator getSecretKeySaltGenerator() {
        return saltGenerator != null ?
                saltGenerator :
                (secretKeySalt == null ?
                        null :
                        new FixedBase64ByteArraySaltGenerator(secretKeySalt));
    }

    @SneakyThrows
    private IvGenerator instantiateIvGenerator() {
        return (IvGenerator)Class.forName(this.ivGeneratorClassName).newInstance();
    }

    public IvGenerator getActualIvGenerator() {
        return Optional.ofNullable(ivGenerator).orElseGet(this::instantiateIvGenerator);
    }
}
