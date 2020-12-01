import crypto from 'crypto'
import { aeadEncrypt, aeadDecrypt } from './chacha20Poly1305.js'
import { DEM_NONCE_SIZE, DEM_KEYSIZE } from './config.js'

class UmbralDEM {
    constructor (symKey) {
        /*
          Initializes an UmbralDEM object. Requires a key to perform
          ChaCha20-Poly1305.
          */

        if (symKey.length !== DEM_KEYSIZE) {
            throw (Error(`Invalid key size, must be ${DEM_KEYSIZE} bytes"`))
        }

        this.key = symKey
    }

    encrypt (data, authenticatedData = null) {
        /*
          Encrypts data using ChaCha20-Poly1305 with optional authenticated data.
          */

        const nonce = crypto.randomBytes(DEM_NONCE_SIZE)
        const encData = aeadEncrypt(
            this.key, nonce, data, authenticatedData.length === null ? new Uint8Array() : authenticatedData)
        return Uint8Array.from([...new Uint8Array(nonce), ...encData])
    }

    decrypt (ciphertext, authenticatedData = null) {
        const nonce = new Uint8Array([...ciphertext]).slice(0, DEM_NONCE_SIZE)
        const encData = new Uint8Array([...ciphertext]).slice(DEM_NONCE_SIZE, ciphertext.length)
        // console.log('key', this.key)
        const result = aeadDecrypt(this.key, nonce, encData, authenticatedData === null ? new Uint8Array() : authenticatedData)

        // console.log(result)
        return result
    }
}

export { UmbralDEM }