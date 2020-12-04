import {defaultCurve} from "./config.js";
import {CurveBN} from "./curvebn.js";
import {base64ToArrayBuffer, fromHexString, getASN1_fromQ, mergeTypedArrays} from "./utils.js";
import elliptic from "elliptic";
import {unsafeHash2Point} from "./randomOracles";

class CorrectnessProof {
    // not sure what this is for atm... not really used elsewhere
    // todo : unit tests
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

// noinspection JSCheckFunctionSignatures
class kFrag {
    // todo : unit tests
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
            atob(data.identifier),
            new CurveBN(Buffer.from(base64ToArrayBuffer(data.bn_key))),
            defaultCurve.curve.decodePoint(atob(data.point_commitment)),
            defaultCurve.curve.decodePoint(atob(data.point_precursor)),
            atob(data.signature_for_proxy),
            atob(data.signature_for_bob),
            new Uint8Array([atob(data.key_in_signature)])
        );
    }

    asJson() {
        return JSON.stringify({
            "identifier": btoa(this._identifier),
            "bn_key": btoa(this._bn_key.asBytes()),
            "point_commitment": btoa(elliptic.utils.toArray(this.point_commitment.encodeCompressed())),
            "point_precursor": btoa(elliptic.utils.toArray(this.point_precursor.encodeCompressed())),
            "signature_for_proxy": btoa(this.signature_for_proxy),
            "signature_for_bob": btoa(this.signature_for_bob),
            "key_in_signature": btoa(this.key_in_signature)
        })
    }


    // todo: unit tests
    
    verify(signing_pubkey, delegating_pubkey, receiving_pubkey, curve, metadata) {
        const u = unsafeHash2Point(curve.g.encodeCompressed(), "NuCypher/UmbralParameters/u", curve); // static
        const correct_commitment = this.point_commitment.eq(u.mul(this._bn_key)); // this might or might not fuck up

        // combine all params to get hash
        let output = mergeTypedArrays(this.identifier, mergeTypedArrays(this.point_commitment.encodeCompressed(), mergeTypedArrays(fromHexString(getASN1_fromQ(this.point_precursor)), this.key_in_signature)))

        if(this.delegating_key_in_sig())
            output = mergeTypedArrays(output, fromHexString(getASN1_fromQ(delegating_pubkey)))
        if(this.receiving_key_in_sig())
            output = mergeTypedArrays(output, fromHexString(getASN1_fromQ(receiving_pubkey)))
        if(metadata != null || metadata !== "")
            output = mergeTypedArrays(output, metadata)

        var ec = new elliptic.eddsa('ed25519');

        // might need to decode point first
        const pub = ec.keyFromPublic(signing_pubkey);

        return pub.verify(output, this.signature_for_proxy) && correct_commitment;
    }

    // todo: verify_for_capsule
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
    // todo: unit tests
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

    // todo: proof correctness unit test
    proof_correctness(capsule, kFrag, metadata) {
        const curve = capsule.curve;
        if (capsule.notValid())
            throw Error("Capsule Verification failed. Capsule Tampered.")

        const rk = kFrag.bn_key;
        const t = CurveBN.genRand();

        const u = unsafeHash2Point(curve.g.encodeCompressed(), "NuCypher/UmbralParameters/u", curve); // static

        const e2 = capsule.pointE.mul(t)
        const v2 = capsule.pointV.mul(t)
        const u2 = u.mul(t);

        let input = [
            ...capsule.pointE.encodeCompressed(),
            ...capsule.pointV.encodeCompressed(),
            ...this.e1.encodeCompressed(),
            ...this.v1.encodeCompressed(),
            ...u.encodeCompressed(),
            ...kFrag.point_commitment.encodeCompressed(),
            ...e2.encodeCompressed(),
            ...v2.encodeCompressed(),
            ...u2.encodeCompressed(),
        ]
        if(metadata != null && metadata !== "")
            input = input.push(Uint8Array.from([...metadata]))

        const h = CurveBN.hashToCurvebn(input, curve)
        // t + h * rk
        const z3 = t.add(h.mul(rk))

        this.proof = new CorrectnessProof(e2, v2, kFrag.point_commitment, u2, z3, kFrag.signature_for_bob )
    }

    // todo: verify correctness



    // todo: reEncrypt
    reEncrypt(kfrag, capsule, provide_proof, proxy_meta, verify_kFrag) {
        return new cFrag();
    }
}