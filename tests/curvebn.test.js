import assert from "assert";
import {toHexString} from "../src/utils.js";
import {CurveBN} from "../src/curvebn.js";
import {defaultCurve} from "../src/config.js";
import {BN} from "bn.js"

describe('hash2curve', function() {
    it('output is same with java version', function() {
        const utf8Encode = new TextEncoder();
        assert.equal((toHexString(CurveBN.hashToCurvebn([utf8Encode.encode("HELLO WORLD")],CurveBN.genRand().curve).asBytes())), "0839CC346AA7C896379F51E44575375AD4A1B7EEEDC92C61BD85BFE116533259");
    });
});

describe('arithmetics', function() {
    it('lambdaCoeff is same as java version', function() {

        const id = new CurveBN(new BN("b5aa4fdd5f4476d9cde31e01aa11e0f8f5bde05f5100f9db8e2b0baeb91692d7", 16), defaultCurve.curve)

        const id_s = [
            new CurveBN(new BN("b5aa4fdd5f4476d9cde31e01aa11e0f8f5bde05f5100f9db8e2b0baeb91692d7", 16), defaultCurve.curve),
            new CurveBN(new BN("f575f5c7c78b62b11d4463821056d7af0e94f83bf4c1202fc6410a7a88b8f861", 16), defaultCurve.curve),
            new CurveBN(new BN("b9136323dd6fe6244eda7350337b13dc9030dd6541c7e5f2304688a8bd3550e1", 16), defaultCurve.curve),
            new CurveBN(new BN("f99c31b318c553cd6d20b88245061fc56207ca1793ab8af0cc23f1d5c946b1c4", 16), defaultCurve.curve),
            new CurveBN(new BN("bddd6885ebfb9699294655f1c225bbd6f6b0e3ac54063b292222a4ece1dec0a5", 16), defaultCurve.curve),
            new CurveBN(new BN("e0f27f1d972f20caada310f9e903a0b19967b6f939ac9a3e9c75715ada242e9c", 16), defaultCurve.curve),
            new CurveBN(new BN("d20ed2a11713c129d7e90bf37fa2d2e5b9895f3b1f08865b8e6dcc33cfd8329d", 16), defaultCurve.curve),
            new CurveBN(new BN("e9aca197ee08249cc7d3a6d0b11df69f5f10e451b849e2311eab31af87d815b7", 16), defaultCurve.curve),
            new CurveBN(new BN("56b56d8068aa4e3e09d9761812492b3dbba811735291a224b913332671a510d9", 16), defaultCurve.curve),
            new CurveBN(new BN("d93f75df1b1b2346cb60ad140619cd127bcfe29a0aa133d5f7304c759c144e6b", 16), defaultCurve.curve)
        ]

        assert.equal(toHexString(CurveBN.lambdaCoeff(id,id_s).asBytes()), "0C2E68C630E4493477635815B78D3C241541F77D4289B9C8AB209ECE1250BBE8")
    });
});
