import {defaultCurve} from "../src/config.js";
import {getASN1_pub} from "../src/utils.js";
import assert from "assert";
import {getASN1_fromQ} from "../src/utils.js";

describe('public/private key serialization', function() {
    it('public key from bigint', function() {
        var key = { x: defaultCurve.curve.decodePoint("0370EFBCB1147228A3B7A19EA78536143F2AB43205EDB94DD646870AA727468296", 'hex').x.toString('hex'), y: defaultCurve.curve.decodePoint("0370EFBCB1147228A3B7A19EA78536143F2AB43205EDB94DD646870AA727468296", 'hex').y.toString('hex') };
        assert.equal(getASN1_pub(key).toUpperCase(), "308201313081EA06072A8648CE3D02013081DE020101302B06072A8648CE3D010102207FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED304404202AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A14404207B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C8640441042AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D902201000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED0201080342000470EFBCB1147228A3B7A19EA78536143F2AB43205EDB94DD646870AA72746829663D5F0D01F71D3556A8CE6684FA466D51BF40A0F059BD3B112555E93533D05AB")
        assert.equal(getASN1_fromQ("0370EFBCB1147228A3B7A19EA78536143F2AB43205EDB94DD646870AA727468296").toUpperCase(), "308201313081EA06072A8648CE3D02013081DE020101302B06072A8648CE3D010102207FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED304404202AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A14404207B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C8640441042AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D902201000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED0201080342000470EFBCB1147228A3B7A19EA78536143F2AB43205EDB94DD646870AA72746829663D5F0D01F71D3556A8CE6684FA466D51BF40A0F059BD3B112555E93533D05AB")
    });
});