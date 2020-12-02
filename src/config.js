import elliptic from 'elliptic'
import curves from 'elliptic'

import hash from 'hash.js'
const EC = elliptic.ec

// define curve25519-weier
const curve = new curves.curves.PresetCurve({
    type: 'short',
    prime: 'p25519',
    p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
    a: '2aaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaa984914a144',
    b: '7b425ed097b425ed 097b425ed097b425 ed097b425ed097b4 260b5e9c7710c864',
    n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
    hash: hash.sha256,
    gRed: false,
    g: [
        '2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a',
        '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9'
    ]
});

const defaultCurve = EC(curve);

// NOTE TO SELF!!! we are using weierstrass form in java, always look up weierstrass form of curve25519
//const defaultCurve = new EC('curve25519-weier')
const PUBLIC_KEY_LENGTH = 33;
const CAPSULE_LENGTH = 98;
const DEM_NONCE_SIZE = 12;
const DEM_KEYSIZE = 32;

export {
    defaultCurve,
    PUBLIC_KEY_LENGTH,
    CAPSULE_LENGTH,
    DEM_NONCE_SIZE,
    DEM_KEYSIZE
}