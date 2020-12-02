import blake2b512 from 'bcrypto/lib/blake2b512.js'
import { DEM_KEYSIZE } from './config.js'
import HKDF from 'bcrypto/lib/hkdf.js'
import {fromHexString} from "./utils.js";

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
function getInt64Bytes(x) {
    return [x,(x<<8),(x<<16),(x<<24)].map(z=> z>>>24)
}

function unsafeHash2Point (data, label, curve) {
    // this is... annoying... if we dont do this, it breaks the java version, the java version does some unnecessary checks but unless we rewrite it, this is here to stay
    /*
        console.log(data.length)
        const label_data = Buffer.from([
                ...Buffer.from(new Uint8Array(getInt64Bytes(label.length))),
                ...Buffer.from(label),
                ...Buffer.from(new Uint8Array(getInt64Bytes(data.length))),
                ...Buffer.from(data)
        ]);

        console.log(toHexString(label_data))
        let i = 0;
        while (i < 4294967296) {
            const idata = Buffer.from(new Uint8Array(getInt64Bytes(i)));

            const hashFunction = blake2b(64)
            hashFunction.update(new Uint8Array(64))
            hashFunction.update(Buffer.from([...label_data, ...idata]))

            let digest = hashFunction.digest('binary');
            let sign = 3;
            if (digest[0] != 1)
                sign = 2;
            digest[0] = sign;
            console.log(i + " " + toHexString(digest.slice(0,33)))
            try {
                return curve.decodePoint(fromHexString(toHexString(digest.slice(0,33))))
            }catch (e) {
                console.log(e)
            }
            i++;
        }
    */

    return curve.decodePoint(fromHexString("027769A36D924905BDE272D32FE1C9663DF7671DCF689CE9FF31FC03D1A562A73C"))
}

export { kdf, kdf_raw, unsafeHash2Point }