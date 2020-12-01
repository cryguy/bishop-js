import blake2b512 from 'bcrypto/lib/blake2b512.js'
import { DEM_KEYSIZE } from './config.js'
import HKDF from 'bcrypto/lib/hkdf.js'

function kdf (ecpoint, keyLength = DEM_KEYSIZE, salt = '', info = '') {
    const ikm = Buffer.from(ecpoint.encodeCompressed())
    salt = Buffer.from(salt)
    info = Buffer.from(info)

    const hkdf = HKDF(blake2b512, ikm, salt, info)
    return Uint8Array.from(hkdf.generate(keyLength))
}

function kdf_raw (bytes, keyLength = DEM_KEYSIZE, salt = '', info = '') {
    const ikm = Buffer.from(bytes)
    salt = Buffer.from(salt)
    if (info == null)
        info = ''
    info = Buffer.from(info)

    const hkdf = new HKDF(blake2b512, ikm, salt, info)
    return Uint8Array.from(hkdf.generate(keyLength))
}

// todo: hash2curvepoint




export { kdf, kdf_raw }