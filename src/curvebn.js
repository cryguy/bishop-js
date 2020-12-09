import elliptic from 'elliptic'
import BN from 'bn.js'
import { defaultCurve } from './config.js'
import crypto from 'crypto'
import blake2b from 'blake2b'
import {toHexString} from "./utils.js";

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
    sub (other) {
        if (other.bn !== undefined) {
            other = other.bn
        }

        let res = this.bn.sub(other)

        return new CurveBN(res.divmod(this.curve.n).mod, this.curve)
    }

    mul (other) {
        if (other.bn !== undefined) {
            other = other.bn
        }
        const res = this.bn.mul(other)

        return new CurveBN(res.divmod(this.curve.n).mod, this.curve)
    }

    inv(){
        return new CurveBN(this.bn.invm(this.curve.n))
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
            //console.log(toHexString(item))
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

    div(other){
        if (other.bn !== undefined) {
            other = other.bn
        }

        return this.mul(other.invm(this.curve.n))
    }

    static lambdaCoeff(id, selected_ids){
        let ids = [];

        for (let j = 0; j < selected_ids.length; j++) {
            if(!selected_ids[j].eq(id))
                ids.push(selected_ids[j])
        }

        if (ids.length === 0)
            return new CurveBN(new BN(1),defaultCurve.curve)

        let result = ids[0].div(ids[0].sub(id.bn))

        for (let i = 1; i < ids.length; i++) {
            result = result.mul(ids[i].div(ids[i].sub(id.bn)))
        }

        return result
    }

    static poly_eval(coeff, x){
        let result = coeff[coeff.length-1];
        for (let i = 2; i < coeff.length + 1; i++) {
            result = coeff[coeff.length-i].add(result.mul(x));
        }
        return result;
    }

}

export { CurveBN }