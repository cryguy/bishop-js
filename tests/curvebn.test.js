import assert from "assert";
import {toHexString} from "../src/utils.js";
import {CurveBN} from "../src/curvebn.js";

describe('hash2curve', function() {
    it('output is same with java version', function() {
        const utf8Encode = new TextEncoder();
        assert.equal((toHexString(CurveBN.hashToCurvebn([utf8Encode.encode("HELLO WORLD")],CurveBN.genRand().curve).asBytes())), "0839CC346AA7C896379F51E44575375AD4A1B7EEEDC92C61BD85BFE116533259");
    });
});
