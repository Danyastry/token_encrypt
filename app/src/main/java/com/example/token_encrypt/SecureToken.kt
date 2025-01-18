package com.example.token_encrypt

import android.content.Context
import android.content.SharedPreferences

class SecureToken(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_ENCRYPTED_TOKEN = ""
    }

    fun saveToken(token: String) {
        val encryptedValue = CryptoHelper.encryptData(token)
        prefs.edit()
            .putString(KEY_ENCRYPTED_TOKEN, encryptedValue)
            .apply()
    }

    fun getToken(): String? {
        val encryptedValue = prefs.getString(KEY_ENCRYPTED_TOKEN, null) ?: return null
        return try {
            CryptoHelper.decryptData(encryptedValue)
        } catch (e: Exception) {
            null
        }
    }

    fun clearToken() {
        prefs.edit()
            .remove(KEY_ENCRYPTED_TOKEN)
            .apply()
    }

}