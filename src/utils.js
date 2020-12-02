import base64js from 'base64-js'
import {defaultCurve} from "./config.js";

function toHexString (byteArray) {
    return Array.prototype.map.call(byteArray, x => ('00' + x.toString(16)).slice(-2)).join('').toUpperCase()
}

export function getASN1_fromQ(q){
    var Q = defaultCurve.curve.decodePoint(q, 'hex');
    return getASN1_pub({x:Q.getX().toString('hex'), y:Q.getY().toString('hex')})
}

export function getASN1_pub(key){
    // https://lapo.it/asn1js/ - validator
    // https://stackoverflow.com/questions/56772982/build-pem-file-by-having-ec-public-key-coordinates

    // AlgorithmIdentifier
    // 30 XB = XB = 9 + ...
    // 06 07 2A 86 48 CE 3D 02 01 - 9
    //const algoIdentifier = "06072A8648CE3D0201"; // id-ecPublicKey (1.2.840.10045.2.1)
    // 2^255 - 19
    // 02207FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    // SubjectPublicKeyInfo.subjectPublicKey
    // 03 XC 00 = XC = 64 + 2 (00 and 04)
    // keyfield = 64 + 2
    // 03 42 00 04 x(32) y(32)

    // curve info string for curve25519 ^ construction method as above
    const curve_info =  "3081EA06072A8648CE3D02013081DE020101302B06072A8648CE3D01010220" +
                        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                        "ED304404202AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                        "AA984914A14404207B425ED097B425ED097B425ED097B425ED097B425ED097" +
                        "B4260B5E9C7710C8640441042AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                        "AAAAAAAAAAAAAAAAAAAAAD245A20AE19A1B8A086B4E01EDD2C7748D14C923D" +
                        "4D7E6D7C61B229E9C5A27ECED3D90220100000000000000000000000000000" +
                        "0014DEF9DEA2F79CD65812631A5CF5D3ED020108";

    const keyfield = "03420004" + key.x.toString().padStart(64,"0") + key.y.toString().padStart(64,"0")
    const before_final = curve_info + keyfield;

    // 82 01 31 = 2 bytes, 01 31 = 305 in hex
    return "30820131"+before_final;
}


export function base64ToArrayBuffer(signature) {
    var binary_string = atob(signature);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}


function mergeTypedArrays(a, b) {
    // Checks for truthy values on both arrays
    if(!a && !b) throw 'Please specify valid arguments for parameters a and b.';

    // Checks for truthy values or empty arrays on each argument
    // to avoid the unnecessary construction of a new array and
    // the type comparison
    if(!b || b.length === 0) return a;
    if(!a || a.length === 0) return b;

    // Make sure that both typed arrays are of the same type
    if(Object.prototype.toString.call(a) !== Object.prototype.toString.call(b))
        throw 'The types of the two arguments passed for parameters a and b do not match.';

    const c = new a.constructor(a.length + b.length);

    c.set(a);
    c.set(b, a.length);

    return c;
}


function fromHexString (str) {
    var a = []
    for (var i = 0, len = str.length; i < len; i += 2) {
        a.push(parseInt(str.substr(i, 2), 16))
    }
    return new Uint8Array(a)
}

function toBase64 (bytes) {
    return base64js.fromByteArray(bytes)
}

function fromBase64 (base64) {
    return base64js.toByteArray(base64)
}

export { toHexString, fromHexString, toBase64, fromBase64, mergeTypedArrays }