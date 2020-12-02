import assert from "assert";
import {fromHexString, toHexString} from "../src/utils.js";
import {unsafeHash2Point} from "../src/randomOracles.js";
import {defaultCurve} from "../src/config.js";
import {BN} from 'bn.js'
describe('unsafeHash2Point', function() {
    it('output is same with java version', function() {
        //console.log(defaultCurve.g.encodeCompressed())
        assert.equal(toHexString(unsafeHash2Point(defaultCurve.g.encodeCompressed(),"NuCypher/UmbralParameters/u", defaultCurve.curve).encodeCompressed()), "027769A36D924905BDE272D32FE1C9663DF7671DCF689CE9FF31FC03D1A562A73C");
    });
    it('multiplication will produce same result as java version', function () {
        assert.equal(toHexString(unsafeHash2Point(defaultCurve.g.encodeCompressed(),"NuCypher/UmbralParameters/u", defaultCurve.curve).mul(new BN('c88552290366dc6a3e7be38aea8feb0d4288269cb2f30261347a6ed98b1fb38', 16)).encodeCompressed()), "022B2984A56050044DCEFF9E994A0E5F063F3DD346F8293A3226B2EB1E828EC127")
    })
});
