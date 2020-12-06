import {defaultCurve, EdDSA} from "./config.js";
import {CurveBN} from "./curvebn.js";
import {
    base64ToArrayBuffer,
    fromHexString,
    getASN1_pub,
    mergeTypedArrays,
    toHexString
} from "./utils.js";
import elliptic from "elliptic";
import {unsafeHash2Point} from "./randomOracles.js";
import {BN} from 'bn.js'

class CorrectnessProof {

    constructor(e2, v2, commitment, pok, sig_key, signature, metadata) {
        this.e2 = e2;
        this.v2 = v2;
        this.commitment = commitment;
        this.pok = pok;
        this.sig_key = sig_key;
        this.signature = signature;
        this.metadata = metadata;
    }

    // only supports the default curve = 25519... might be a problem for the future
    static fromJson(json) {
        const data = JSON.parse(json);
        const metadata = data.metadata ? atob(data.metadata) : null;
        return new CorrectnessProof(
            defaultCurve.curve.decodePoint(atob(data.e2)),
            defaultCurve.curve.decodePoint(atob(data.v2)),
            defaultCurve.curve.decodePoint(atob(data.commitment)),
            defaultCurve.curve.decodePoint(atob(data.pok)),
            new CurveBN(Buffer.from(base64ToArrayBuffer(data.sig_key))),
            atob(data.signature),
            metadata
        );
    }

    asJson() {
        if (this.metadata != null)
            return JSON.stringify({
                "e2": btoa(elliptic.utils.toArray(this.e2.encodeCompressed())),
                "v2": btoa(elliptic.utils.toArray(this.v2.encodeCompressed())),
                "commitment": btoa(elliptic.utils.toArray(this.commitment.encodeCompressed())),
                "pok": btoa(elliptic.utils.toArray(this.pok.encodeCompressed())),
                "sig_key": btoa(this.sig_key.asBytes()),
                "signature": btoa(this.signature),
                "metadata": btoa(this.metadata)
            });
        else
            return JSON.stringify({
                "e2": btoa(elliptic.utils.toArray(this.e2.encodeCompressed())),
                "v2": btoa(elliptic.utils.toArray(this.v2.encodeCompressed())),
                "commitment": btoa(elliptic.utils.toArray(this.commitment.encodeCompressed())),
                "pok": btoa(elliptic.utils.toArray(this.pok.encodeCompressed())),
                "sig_key": btoa(this.sig_key.asBytes()),
                "signature": btoa(this.signature)
            });

    }
}


class kFrag {
    constructor(identifier, bn_key, point_commitment, point_precursor, signature_for_proxy, signature_for_bob, key_in_signature) {
        this.identifier = identifier;
        this.bn_key = bn_key;
        this.point_commitment = point_commitment;
        this.point_precursor = point_precursor;

        this.signature_for_proxy = signature_for_proxy;
        this.signature_for_bob = signature_for_bob;

        this.key_in_signature = key_in_signature;
    }

    static fromJson(json) {
        const data = JSON.parse(json);

        return new kFrag(
            base64ToArrayBuffer(data.identifier),
            new BN(new Uint8Array(base64ToArrayBuffer(data.bn_key))),
            defaultCurve.curve.decodePoint(atob(data.point_commitment)),
            defaultCurve.curve.decodePoint(atob(data.point_precursor)),
            base64ToArrayBuffer(data.signature_for_proxy),
            base64ToArrayBuffer(data.signature_for_bob),
            new Uint8Array(base64ToArrayBuffer(data.key_in_signature))
        );
    }

    asJson() {
        return JSON.stringify({
            "identifier": btoa(this.identifier),
            "bn_key": btoa(this.bn_key.toArray('be', defaultCurve.curve.n.byteLength())),
            "point_commitment": btoa(elliptic.utils.toArray(this.point_commitment.encodeCompressed())),
            "point_precursor": btoa(elliptic.utils.toArray(this.point_precursor.encodeCompressed())),
            "signature_for_proxy": btoa(this.signature_for_proxy),
            "signature_for_bob": btoa(this.signature_for_bob),
            "key_in_signature": btoa(this.key_in_signature)
        })
    }

    verify(signing_pubkey, delegating_pubkey, receiving_pubkey, curve, metadata) {
        const u = unsafeHash2Point(curve.g.encodeCompressed(), "NuCypher/UmbralParameters/u", curve); // static
        const correct_commitment = this.point_commitment.eq(u.mul(this.bn_key)); // this might or might not fuck up

        let output = mergeTypedArrays(Buffer.from(this.identifier), mergeTypedArrays(Buffer.from(this.point_commitment.encodeCompressed()), mergeTypedArrays(fromHexString(getASN1_pub(this.point_precursor)), this.key_in_signature)))

        if(this.delegating_key_in_sig())
            output = mergeTypedArrays(output, fromHexString(getASN1_pub(delegating_pubkey)))

        if(this.receiving_key_in_sig())
            output = mergeTypedArrays(output, fromHexString(getASN1_pub(receiving_pubkey)))

        if(metadata != null || metadata !== "")
            output = mergeTypedArrays(output, metadata)

        // might need to decode point first
        const pub = EdDSA.keyFromPublic(toHexString(signing_pubkey), 'hex');

        return pub.verify(output, toHexString(Buffer.from(this.signature_for_proxy))) && correct_commitment;
    }

    verify_for_capsule(capsule) {
        return this.verify(capsule.CfragCorrectnessKeys.verifying,capsule.CfragCorrectnessKeys.delegating, capsule.CfragCorrectnessKeys.receiving, capsule.curve, capsule.metadata)
    }

    delegating_key_in_sig() {
        return this.key_in_signature[0] === 1 || this.key_in_signature[0] === 3;
    }

    receiving_key_in_sig() {
        return this.key_in_signature[0] === 2 || this.key_in_signature[0] === 3;
    }
}


class cFrag {
    constructor(e1, v1, kFrag_id, precursor, correctnessProof) {
        this.e1 = e1;
        this.v1 = v1;
        this.kFrag_id = kFrag_id;
        this.precursor = precursor;
        this.proof = correctnessProof;
    }

    static fromJson(json) {
        const data = JSON.parse(json);
        const proof = data.proof ? CorrectnessProof.fromJson(data.proof) : null;
        return new cFrag(
            defaultCurve.curve.decodePoint(atob(data.e1)),
            defaultCurve.curve.decodePoint(atob(data.e2)),
            atob(data.kfrag_id),
            defaultCurve.curve.decodePoint(atob(data.precursor)),
            proof
        );
    }

    asJson() {
        return JSON.stringify({
            "e1": btoa(elliptic.utils.toArray(this.e1.encodeCompressed())),
            "v1": btoa(elliptic.utils.toArray(this.v1.encodeCompressed())),
            "kfrag_id": btoa(this.kFrag_id),
            "precursor": btoa(elliptic.utils.toArray(this.precursor.encodeCompressed())),
            "proof": this.proof ? this.proof.asJson() : null
        });
    }

    proof_correctness(capsule, kFrag, metadata, not_random = "") {
        const curve = capsule.curve;
        if (capsule.notValid())
            throw Error("Capsule Verification failed. Capsule Tampered.")

        const u = unsafeHash2Point(curve.g.encodeCompressed(), "NuCypher/UmbralParameters/u", curve); // static
        const rk = kFrag.bn_key;

        let t = CurveBN.genRand();

        if (not_random !== "") {
            t = new CurveBN(new BN(not_random, 16), defaultCurve.curve)
        }

        const e2 = capsule.pointE.mul(t.bn)
        const v2 = capsule.pointV.mul(t.bn)
        const u2 = u.mul(t.bn)
        let input = [
            capsule.pointE.encodeCompressed(),
            this.e1.encodeCompressed(),
            e2.encodeCompressed(),
            capsule.pointV.encodeCompressed(),
            this.v1.encodeCompressed(),
            v2.encodeCompressed(),
            u.encodeCompressed(),
            kFrag.point_commitment.encodeCompressed(),
            u2.encodeCompressed(),
        ]

        if(metadata != null)
            input.push(metadata)


        const h = CurveBN.hashToCurvebn(input, curve)

        // t + h * rk
        let z3 = t.add(h.mul(rk))

        // console.log("H : " + h.bn.toString(10))
        // console.log("T : "  + t.bn.toString(16))
        // console.log("H * rk : " + h.mul(rk).bn.toString(16))
        // console.log(z3.bn.toString(16))

        this.proof = new CorrectnessProof(e2, v2, kFrag.point_commitment, u2, z3, kFrag.signature_for_bob )
    }

    verify_correctness(capsule){
        if(this.proof == null)
            throw Error("No Proof Provided")
        const u = unsafeHash2Point(capsule.curve.g.encodeCompressed(), "NuCypher/UmbralParameters/u", capsule.curve); // static
        let input = [
            capsule.pointE.encodeCompressed(),
            this.e1.encodeCompressed(),
            this.proof.e2.encodeCompressed(),
            capsule.pointV.encodeCompressed(),
            this.v1.encodeCompressed(),
            this.proof.v2.encodeCompressed(),
            u.encodeCompressed(),
            this.proof.commitment.encodeCompressed(),
            this.proof.pok.encodeCompressed(),
        ]

        if(this.proof.metadata != null && this.proof.metadata !== "")
            input.push(Uint8Array.from([...this.proof.metadata]))

        const h = CurveBN.hashToCurvebn(input, capsule.curve)


        let output = mergeTypedArrays(Buffer.from(this.kFrag_id), mergeTypedArrays(fromHexString(getASN1_pub(capsule.CfragCorrectnessKeys.delegating)), mergeTypedArrays(fromHexString(getASN1_pub(capsule.CfragCorrectnessKeys.receiving)), mergeTypedArrays(Buffer.from(this.proof.commitment.encodeCompressed()), fromHexString(getASN1_pub(this.precursor))))))

        if (capsule.metadata != null && capsule.metadata !== "")
        {
            output = mergeTypedArrays(output, capsule.metadata)
        }

        const pub = EdDSA.keyFromPublic(toHexString(capsule.CfragCorrectnessKeys.verifying), 'hex');

        const z3 = this.proof.sig_key
        const correct_e = capsule.pointE.mul(z3.bn).eq(this.proof.e2.add(this.e1.mul(h.bn)))
        const correct_v = capsule.pointV.mul(z3.bn).eq(this.proof.v2.add(this.v1.mul(h.bn)))
        const correct_rk = u.mul(z3.bn).eq(this.proof.pok.add(this.proof.commitment.mul(h.bn)))

        return pub.verify(output, toHexString(Buffer.from(this.proof.signature))) && correct_e && correct_v && correct_rk
    }

    static reEncrypt(kfrag, capsule, provide_proof, proxy_meta, verify_kFrag, not_random = "") {
        if (capsule.notValid())
            throw Error("Capsule verification failed");
        if (verify_kFrag)
            if(!kfrag.verify_for_capsule(capsule))
                throw Error("Invalid kFrag");
        const rk = kfrag.bn_key;

        const e1 = capsule.pointE.mul(rk);
        const v1 = capsule.pointV.mul(rk);

        const cfrag = new cFrag(e1,v1,kfrag.identifier, kfrag.point_precursor)

        if (provide_proof)
            cfrag.proof_correctness(capsule, kfrag, proxy_meta, not_random);

        return cfrag;
    }
}

export {kFrag,cFrag,CorrectnessProof}