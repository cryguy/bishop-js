import elliptic from 'elliptic'
import ModPoint from "simple-js-ec-math/src/modpoint.js";
import Curve from "simple-js-ec-math/src/curve.js";
import BN from "bn.js"
import bigInt from "big-integer";

const EC = elliptic.ec
// NOTE TO SELF!!! we are using weierstrass form in java, always look up weierstrass form of curve25519
const defaultCurve = new EC('curve25519-weier')
const PUBLIC_KEY_LENGTH = 33
const CAPSULE_LENGTH = 98
const DEM_NONCE_SIZE = 12
const DEM_KEYSIZE = 32
const g = new ModPoint(9, 14781619447589544791020593568409986887264606134616475288964881837755586237401)
const curve = new Curve(BigInt(486662), BigInt(1), bigInt('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16),57896044618658097711785492504343953926634992332820282019728792003956564819949n, g)

export {
    curve,
    defaultCurve,
    PUBLIC_KEY_LENGTH,
    CAPSULE_LENGTH,
    DEM_NONCE_SIZE,
    DEM_KEYSIZE
}