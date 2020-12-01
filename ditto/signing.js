import { CurveBN } from './curvebn.js'
import { defaultCurve } from './config.js'
import { toHexString, fromHexString } from './utils.js'
import sha256 from 'js-sha256'

class Signature {
    constructor (r, s) {
        this.r = new CurveBN(r)
        this.s = new CurveBN(s)
    }

    static expectedBytesLength () {
        return defaultCurve.n.byteLength() * 2
    }

    asBytes () {
        return Uint8Array.from([...this.r.asBytes(), ...this.s.asBytes()])
    }

    verify (message, verifyingKey) {
        const keypair = defaultCurve.keyFromPublic(verifyingKey)
        return keypair.verify(sha256.sha256(message), { r: this.r.bn, s: this.s.bn })
    }

    static fromBytes (bytes) {
        const r = CurveBN.fromBytes(bytes.slice(0, this.expectedBytesLength() / 2), 16)
        const s = CurveBN.fromBytes(bytes.slice(this.expectedBytesLength() / 2, bytes.length), 16)
        return new Signature(r.bn, s.bn)
    }

    static fromHex (hex) {
        return Signature.fromBytes(fromHexString(hex))
    }

    eq (other) {
        return toHexString(this.asBytes()) === toHexString(other.asBytes())
    }
}

class Signer {
    constructor (signingKey) {
        this.signingKey = signingKey
        this.pubKey = this.signingKey.getPublic()
    }

    sign (message) {
        message = sha256.sha256(message)
        const sig = this.signingKey.sign(message)
        return new Signature(sig.r, sig.s)
    }
}

export { Signature, Signer }