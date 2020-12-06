import elliptic from 'elliptic'
import {UmbralDEM} from './dem.js'
import {kdf, kdf_raw} from './randomOracles.js'
import {CurveBN} from './curvebn.js'
import {defaultCurve, DEM_KEYSIZE} from './config.js'
import {mergeTypedArrays} from "./utils.js";
import _ from "lodash"
import {fromHexString, base64ToArrayBuffer} from "./utils.js";


// todo: unit tests

class Capsule {
    constructor (pointE, pointV, bnSig, metadata, hash, curve) {
        /*
          pointE: a public key (Point)
          pointV: a public key (Point)
          bnSig: a BN (BIG NUMBER)
        */
        this.curve = curve; // same thing as params
        this.pointE = pointE
        this.pointV = pointV
        this.bnSig = bnSig
        this.metadata = metadata
        this.hash = hash

        this.AttachedCfrags = []
        this.CfragCorrectnessKeys = {
          delegating: null,
          receiving: null,
          verifying: null // type: EdDSAPubKey
        }
    }

    firstCFrag() {
        if (this.AttachedCfrags.length === 0){
            throw Error("No CFrags attached yet")
        }
        return this.AttachedCfrags[0];
    }

    setCorrectnessKey(alice_public, bob_public, alice_verifying){
        this.CfragCorrectnessKeys.delegating = alice_public;
        this.CfragCorrectnessKeys.receiving = bob_public;
        this.CfragCorrectnessKeys.verifying = alice_verifying; // type: EdDSAPubKey
    }

    notValid(){
        const h = CurveBN.hashToCurvebn([this.pointE.encodeCompressed(), this.pointV.encodeCompressed()], this.curve)

        const hash_raw = mergeTypedArrays(fromHexString(this.pointE.encodeCompressed('hex', true)), fromHexString(this.pointV.encodeCompressed('hex', true)));
        const hash = kdf_raw(hash_raw, 32, this.bnSig.asBytes(), this.metadata);

        return !(this.curve.g.mul(this.bnSig.bn).eq(this.pointV.add(this.pointE.mul(h.bn))) && _.isEqual(btoa(this.hash), btoa(hash)))
    }

    asBytes () {
        /*
        Serialize the Capsule into bytes.
        */
        // can be optimized... dw bout it now i guess...
        if (this.metadata != null)
            return Uint8Array.from(
                [
                    ...elliptic.utils.toArray(this.pointE.encodeCompressed()),
                    ...elliptic.utils.toArray(this.pointV.encodeCompressed()),
                    ...elliptic.utils.toArray(this.bnSig.asBytes()),
                    ...this.metadata
                ]
            )
        else
            return Uint8Array.from(
                [
                    ...elliptic.utils.toArray(this.pointE.encodeCompressed()),
                    ...elliptic.utils.toArray(this.pointV.encodeCompressed()),
                    ...elliptic.utils.toArray(this.bnSig.asBytes()),
                ]
            )
    }

    asJson() {
        if (this.metadata != null)
            return JSON.stringify({
                "point_e": btoa(elliptic.utils.toArray(this.pointE.encodeCompressed())),
                "point_v": btoa(elliptic.utils.toArray(this.pointV.encodeCompressed())),
                "signature": btoa(this.bnSig.asBytes()),
                "hash": btoa(this.hash),
                "metadata": btoa(this.metadata)
            })
        else
            return JSON.stringify({
                "point_e": btoa(this.pointE.encodeCompressed()),
                "point_v": btoa(this.pointV.encodeCompressed()),
                "signature": btoa(this.bnSig.asBytes()),
                "hash": btoa(this.hash)
            })
    }


    static fromJson(json, curve_) {
        const data = JSON.parse(json);
        let metadata = null;
        if (data.metadata)
            metadata = atob(data.metadata)


        return new Capsule(defaultCurve.curve.decodePoint(atob(data.point_e)), defaultCurve.curve.decodePoint(atob(data.point_v)), new CurveBN(Buffer.from(base64ToArrayBuffer(data.signature))), metadata, atob(data.hash), curve_);
    }


}

// todo: generate kFrag
// todo: get kFrag

function _decapsulateOriginal (privateKey, capsule, keyLength = DEM_KEYSIZE) {
    const sharedKey = capsule.pointE.add(capsule.pointV).mul(privateKey)
    return kdf(sharedKey, keyLength)
}

function _encapsulate (alicePubkey, metadata, keyLength = DEM_KEYSIZE) {
    // Generates a symmetric key and its associated KEM ciphertext

    const g = alicePubkey.curve.g // the curve's generator point

    const privR = CurveBN.genRand(alicePubkey.curve)
    const pubR = g.mul(privR.bn)

    const privU = CurveBN.genRand(alicePubkey.curve)
    const pubU = g.mul(privU.bn)

    const h = CurveBN.hashToCurvebn([pubR.encodeCompressed(), pubU.encodeCompressed()], alicePubkey.curve)
    const s = privU.add(privR.mul(h))

    // shared_key = (priv_r + priv_u) * alice_pubkey.point_key  # type: Any
    const sharedKey = alicePubkey.mul(
        privR.add(privU).bn
    )

    // i ducking hate javascript...

    // this is in hex...
    const hash_raw = mergeTypedArrays(pubR.encodeCompressed(), pubU.encodeCompressed());

    const hash = kdf_raw(hash_raw, keyLength, s.bn.asBytes(), metadata);

    const key = kdf(sharedKey, keyLength);
    const capsule = new Capsule(pubR, pubU, s, metadata, hash, alicePubkey.curve.params);

    return {
        key, capsule
    }
}

function encrypt (alicePubkey, plaintext) {
    /*
    Performs an encryption using the UmbralDEM object and encapsulates a key
    for the sender using the public key provided.
    Returns the ciphertext and the KEM Capsule.
    */

    if (alicePubkey.curve === undefined) {
        // the key is in hex/array format?
        try {
            alicePubkey = defaultCurve.curve.decodePoint(alicePubkey, 'hex')
        } catch (err) {
            console.error(err)
            throw Error('could not parse public key')
        }
    }

    const { key, capsule } = _encapsulate(alicePubkey, DEM_KEYSIZE)
    const ciphertext = new UmbralDEM(key).encrypt(plaintext, capsule.asBytes())

    return { ciphertext, capsule }
}
/*
decryption_key = bignum of privatekey... this library is fked...
 */

// todo: add cfrag based decryption
function decrypt(ciphertext, capsule, decryption_key, check_proof = true){
    var key = ""
    if (capsule.not_valid()){
        throw Error("Capsule Verification Failed. Capsule tampered.")
    }
    try {
        key = ""
    } catch (e) {
        const sharedKey = capsule.pointE.add(capsule.pointV).mul(decryption_key)
        key = kdf(sharedKey, keyLength)
    }
    return (new UmbralDEM(key)).decrypt(ciphertext, capsule.asBytes())
}


export { encrypt, _encapsulate, _decapsulateOriginal, Capsule }