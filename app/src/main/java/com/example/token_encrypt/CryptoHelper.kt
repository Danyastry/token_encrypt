package com.example.token_encrypt

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object CryptoHelper {
    const val KEY_ALIAS = "secure_key_alias"
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val AES_GCM = "AES/GCM/NoPadding"

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        val existingKey = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existingKey != null) {
            return existingKey.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(false)
            setKeySize(256)
        }.build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    fun encryptData(text: String): String {
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encryptBytes = cipher.doFinal(text.toByteArray(Charsets.UTF_8))

        val combine = iv + encryptBytes

        return Base64.encodeToString(combine, Base64.DEFAULT)
    }

    fun decryptData(base64Data: String): String {
        val secretKey = getOrCreateSecretKey()
        val encryptedBytes = Base64.decode(base64Data, Base64.DEFAULT)

        val ivSize = 12
        val iv = encryptedBytes.copyOfRange(0, ivSize)
        val cipherText = encryptedBytes.copyOfRange(ivSize, encryptedBytes.size)

        val cipher = Cipher.getInstance(AES_GCM)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val decryptedBytes = cipher.doFinal(cipherText)
        return String(decryptedBytes, Charsets.UTF_8)
    }
}