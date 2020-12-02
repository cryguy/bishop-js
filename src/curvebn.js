import elliptic from 'elliptic'
import BN from 'bn.js'
import { defaultCurve } from './config.js'
import crypto from 'crypto'
import blake2b from 'blake2b'

class CurveBN {
    constructor (bignum, curve) {
        this.bn = new BN(bignum)
        this.curve = curve || defaultCurve
    }

    static fromBytes (bytes) {
        return new CurveBN(bytes)
    }

    asBytes () {
        return this.bn.toArray('be', this.curve.n.byteLength())
    }

    add (other) {
        if (other.bn !== undefined) {
            other = other.bn
        }

        let res = new BN()
        res = res.add(this.bn)
        res = res.add(other)

        return new CurveBN(res.divmod(this.curve.n).mod, this.curve)
    }

    mul (other) {
        if (other.bn !== undefined) {
            other = other.bn
        }
        const res = this.bn.mul(other)

        return new CurveBN(res.divmod(this.curve.n).mod, this.curve)
    }

    eq (other) {
        return this.bn.eq(other.bn)
    }

    static genRand (curve = defaultCurve) {
        let rand = new BN(crypto.randomBytes(32), 16)
        while (rand.lt(0) || rand.gt(curve.n)) {
            rand = new BN(crypto.randomBytes(32), 16)
        }
        return new CurveBN(rand, curve)
    }

    static hashToCurvebn (cryptoItems, curve, customizationString = '', hashClass = blake2b) {
        // https://github.com/emilbayes/blake2b
        let input = elliptic.utils.toArray('hash_to_curvebn' + customizationString)
        input = input.concat(Array(64 - input.length).fill(0))

        const hashFunction = hashClass(64)
        hashFunction.update(input)
        cryptoItems.forEach(item => {
            hashFunction.update(item)
        })

        const one = new BN(1)
        // !!! : This could become a problem. idk if the "hex" here is upper case or lower case... blame this if somehow things are wrong
        // - checked with unit test - results are the same
        const hashDigest = new BN(hashFunction.digest('hex'), 'hex')
        const orderMinusOne = curve.n.sub(one)
        const bignum = hashDigest.mod(orderMinusOne).add(one)

        return new CurveBN(bignum, curve)
    }
}

export { CurveBN }