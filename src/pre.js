import elliptic from 'elliptic'
import {UmbralDEM} from './dem.js'
import {kdf_raw} from './randomOracles.js'
import {CurveBN} from './curvebn.js'
import {defaultCurve, DEM_KEYSIZE} from './config.js'
import {getASN1_pub, mergeTypedArrays, sha512} from "./utils.js";
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

        return !(this.curve.g.mul(this.bnSig.bn).eq(this.pointV.add(this.pointE.mul(h.bn))) && (btoa(this.hash) === btoa(hash)))
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

function _decapsulateOriginal (privateKey, capsule, keyLength = DEM_KEYSIZE) {
    let sharedKey = capsule.pointE.add(capsule.pointV).mul(privateKey.getPrivate()).encodeCompressed()
    if (capsule.metadata != null)
        sharedKey = mergeTypedArrays(sharedKey, Buffer.from(capsule.metadata))

    return kdf_raw(sharedKey, keyLength)
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
    //console.log(toHexString(privR.asBytes()) + " E")
    //console.log(toHexString(privU.asBytes()) + " V")
    const hash_raw = mergeTypedArrays(Buffer.from(pubR.encodeCompressed()), Buffer.from(pubU.encodeCompressed()));
    const hash = kdf_raw(hash_raw, keyLength, Buffer.from(s.asBytes()), metadata);

    let key_raw = sharedKey.encodeCompressed();

    if (metadata != null)
        key_raw = mergeTypedArrays(sharedKey.encodeCompressed(), Buffer.from(metadata))

    //console.log("KEY RAW : " + toHexString(key_raw))
    const key = kdf_raw(key_raw, keyLength)

    //const key = kdf(sharedKey, keyLength);
    const capsule = new Capsule(pubR, pubU, s, metadata, hash, alicePubkey.curve);

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

    const { key, capsule } = _encapsulate(alicePubkey,'', DEM_KEYSIZE)
    const ciphertext = new UmbralDEM(key).encrypt(plaintext, capsule.asBytes())

    return { ciphertext, capsule }
}

function _decapsulateRe(receiving, capsule, key_length, metadata){

    const precursor = defaultCurve.keyFromPublic(capsule.firstCFrag().precursor,'hex').getPublic()

    const dh = receiving.derive(precursor).toArray('be', defaultCurve.curve.n.byteLength());


    let bn_xs = []

    capsule.AttachedCfrags.forEach(value =>{

        const items_bn = [
            fromHexString(getASN1_pub(precursor)),
            receiving.getPublic().encodeCompressed(),
            dh,
            sha512("X_COORDINATE"),
        ]
        items_bn.push(Buffer.from(value.kfrag_id));
        bn_xs.push(CurveBN.hashToCurvebn(items_bn, capsule.curve))
    })

    let e_sum = []
    let v_sum = []

    bn_xs.forEach((value, index) => {
        const cfrag = capsule.AttachedCfrags[index]
        if (!precursor.eq(cfrag.precursor))
            throw Error('CFrag not pairwise consistent')
        const lambda_i = CurveBN.lambdaCoeff(value, bn_xs)
        e_sum.push(cfrag.e1.mul(lambda_i.bn))
        v_sum.push(cfrag.v1.mul(lambda_i.bn))
    })

    let e_prime = e_sum[0]
    let v_prime = v_sum[0]

    for (let i = 1; i < e_sum.length; i++) {
        e_prime = e_prime.add(e_sum[i])
        v_prime = v_prime.add(v_sum[i])
    }

    let items = [
        fromHexString(getASN1_pub(precursor)),
        receiving.getPublic().encodeCompressed(),
        dh,
        sha512("NON_INTERACTIVE")
    ];

    if (metadata != null)
        items.push(Buffer.from(metadata))
    const d = CurveBN.hashToCurvebn(items, capsule.curve)


    // todo : throw Error here
    const h = CurveBN.hashToCurvebn([capsule.pointE.encodeCompressed(), capsule.pointV.encodeCompressed()], capsule.curve);

    if (!capsule.CfragCorrectnessKeys.delegating.mul(capsule.bnSig.div(d).bn).eq(v_prime.add(e_prime.mul(h.bn))))
        throw Error('invalid')
    let key = e_prime.add(v_prime).mul(d.bn).encodeCompressed();
    if (metadata != null)
        key = mergeTypedArrays(Buffer.from(key), Buffer.from(metadata))

    return kdf_raw(key,32)
}

function _open_capsule(receiving, capsule, check_proof){
    if(check_proof){
        capsule.AttachedCfrags.forEach(value => {
            if (value.verify(capsule))
                throw Error('Invalid cFrag found!')
        })
    }
    return _decapsulateRe(receiving, capsule, 32, capsule.metadata)
}

// todo: add cfrag based decryption
function decrypt(ciphertext, capsule, decryption_key, check_proof = true){
    let key = "";
    if (capsule.notValid()){
        throw Error("Capsule Verification Failed. Capsule tampered.")
    }
    try {
        key = _decapsulateRe(decryption_key,capsule,32,capsule.metadata)
    } catch (e) {
        key = _decapsulateOriginal(decryption_key,capsule)
    }



    return (new UmbralDEM(key)).decrypt(ciphertext, capsule.asBytes())
}


export { encrypt, _encapsulate, _decapsulateOriginal, Capsule, decrypt }