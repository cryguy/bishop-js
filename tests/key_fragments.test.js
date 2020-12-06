import {defaultCurve, EdDSA} from "../src/config.js";
import {kFrag, cFrag, CorrectnessProof} from "../src/key_fragments.js";
import {Capsule} from "../src/pre.js"
import assert from 'assert';
import _ from "lodash";


/*
alice Private : 32ca18512f2a7be94b7a3b20fdfe099c0b01acc77ca644837ae60413ec51d36
alice Signing : 911B767C66395F2C31CEFAFE1348B5371087C1935327917C3D160741AA16469D
bob Public    : 032D420C9318EBA2A1034368C2423602500C4052D97B6D1AEE5E696406B3D5FACC
Signature : DCB7D149E35E7A004D372E7008DEDFEC2C5A17B5753CC94646382F2DD01345DE3D057876C04D991B361454286346A87E7B7A16EC040EA20E82396DAD0DBF4102
{"bn_key":"DgSHi25B9M2aJeS8Yc89HBZymusSaSVu3yhKkwMDbFo\u003d","identifier":"6AzoijnEfrSEgOGiHtQ9iB5U5Mw0Zs4mEmKI4ziArKY\u003d","key_in_signature":"Aw\u003d\u003d","point_commitment":"AlUFux+RbwIo2AB1W2+W2YCRKPo1WaYBdh2kofU4CDwJ","point_precursor":"Anh0MfylrppjRyLRfPRrtFWfsfvPlproXWj8rZKh+r2K","signature_for_bob":"QQqGKKs1Acq/3nT+7ppPj+rBvDn3bdHQTwNNoRrJ9mDD3KqCIA/lV5fnta+D7fdLLQYiLJyByNBxzHBZ7Vu9BQ\u003d\u003d","signature_for_proxy":"ed11Pa8+5cFiHapuoZp56wzwSfaxv2XSIuXWAP0xszsvpaDkGBOHUaKM3VhFFDk7xgpslT/JPvQ5S6Myl/MPAA\u003d\u003d"}
 */

const alice = defaultCurve.keyFromPrivate("853df22ce4f89326d74429d3a925797034bc881829334a07e1efd606fcf7dd2");
const alice_public = alice.getPublic()
const alice_ed = EdDSA.keyFromSecret("B4B5E3B387CE16AA3754C0836C5A076A90B71E286EF60699FE61F3A0F845369B");

const msgHash = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
const signature = alice_ed.sign(msgHash).toHex();

const bob_public = defaultCurve.keyFromPublic("03749E03A3F7B8326D21ACAE8B3743AE6AC6BF94AE410B89F8EA8980888681C7EA", 'hex').getPublic()
const json_data = "{\"bn_key\":\"CBrWljuEmEm36rQDbMJ783TrM8zNP5lUhIwSf5+GXgg\u003d\",\"identifier\":\"WZ2LGMVtE+fhJ7D76HSsUxaay9TG4J1j+52o8loh3eU\u003d\",\"key_in_signature\":\"Aw\u003d\u003d\",\"point_commitment\":\"AmStHoja+/cU9pP+7b8jGQYA9Ynj3d75UZLggXhbfmEc\",\"point_precursor\":\"AgwCDsfqj6aZmiBO/ZiRRd0AvC+J27pfX41lJUtEN3pi\",\"signature_for_bob\":\"hy4fVGmfGvkqnCDKIQyT7qd8ys2LeUlrdxLvVH99dHZLagpuohFPksCmLX559HhYBSTjTJo+G8qIjY5J2Gv5BA\u003d\u003d\",\"signature_for_proxy\":\"/gcRukOWtqxNMztUB4UCQOmVp6Ot9r94XoCnAIEBntuGPUpxfGmk2xc5QQtUjc8NizE9J35ejYXqucPy66oADw\u003d\u003d\"}\n"
const kfrag = kFrag.fromJson(json_data);

const capsulejson = "{\"hash\":\"sRAychL2Mvlnt/LouInygqSa91yE2DtM1dgOl9ryNQI\u003d\",\"point_e\":\"AlYiYiQ3/+DpDeUVf+0vfCJePzroYlb+xFvl7dxFSjxO\",\"point_v\":\"A04iMkEViNGYLAkLFvd9U+K72ikm8yUkNo9FqKCPedml\",\"signature\":\"DvbidXWlZDOcxVdn46P/XWOsFYzoFMB9QRdsJ8MB/s0\u003d\"}\n"
const capsule = Capsule.fromJson(capsulejson, defaultCurve.curve)
capsule.setCorrectnessKey(alice_public, bob_public, alice_ed.getPublic())

let java_cFrag_raw = {"e1":"AjrbUSXIFaVbu3bqIuJ+uOVtfWg1SrQuJLTXKVt6y3H+","kfrag_id":"WZ2LGMVtE+fhJ7D76HSsUxaay9TG4J1j+52o8loh3eU=","precursor":"AgwCDsfqj6aZmiBO/ZiRRd0AvC+J27pfX41lJUtEN3pi","proof":"{\"commitment\":\"AmStHoja+/cU9pP+7b8jGQYA9Ynj3d75UZLggXhbfmEc\",\"e2\":\"AyE37UNwAn+RAxlHJCNhIV7qMSKRbjx64gZisfdrHMxR\",\"pok\":\"AlqfHtsA5yhJ+3kYwag/tJ6KIwwwYB2bSln4rwz8ix9c\",\"sig_key\":\"Ah8Zoo4ZmCOUaeH6jpKb99gDK6uGsozYAF5E+HOpDO4\u003d\",\"signature\":\"hy4fVGmfGvkqnCDKIQyT7qd8ys2LeUlrdxLvVH99dHZLagpuohFPksCmLX559HhYBSTjTJo+G8qIjY5J2Gv5BA\u003d\u003d\",\"v2\":\"AzcxEx+ISnNNGK/DsAx11nn2tOgXvkitl0fmeUNn5lPJ\"}","v1":"A2lHmVFk4b9rifLr5a2mSSouHD6VkjmngxrQyN0FMcuX"}
let java_cFrag = JSON.stringify(java_cFrag_raw)
const not_random = "df71df6adecfa30cdae9360e2f3c932451ee1d7139a5bf182322fadc3c0ad22"

describe('kFrag', function() {

    it('Deserialization works the same as java and is still valid', function() {
        assert(kfrag.verify(alice_ed.getPublic(), alice_public, bob_public, defaultCurve.curve, ""))
    })
    it('Assert Signing still is the same with java', function () {
        assert.equal(signature,"293113E1606AA86EBD3BB53CDA04E77CA6C282632605FD5D399FB2B7EA282355FCDD35311253E1F2443780D1869ABC463FE18FA12FB3716CC0B788901FFF8508")
    })

    it('Serialization will return the same result as input json', function (){
        assert(_.isEqual(JSON.parse(kfrag.asJson()), JSON.parse(json_data)))
    })
})


describe('cFrag', function (){
    it('reEncrypt has same result as java version', function () {
        // console.log(JSON.stringify(JSON.parse(cFrag.reEncrypt(kfrag, capsule, true, null, true, not_random).asJson())))
        // console.log(JSON.stringify(JSON.parse(cFrag.reEncrypt(kfrag, capsule, true, null, true, not_random).proof.asJson())))
        // console.log(JSON.stringify(JSON.parse(java_cFrag)))
        // console.log(JSON.parse(java_cFrag).proof)
        let cfragJson = JSON.parse(cFrag.reEncrypt(kfrag, capsule, true, null, true, not_random).asJson());
        let parse = JSON.parse(java_cFrag);



        // check proof equality
        assert(_.isEqual(JSON.parse(cfragJson.proof), JSON.parse(parse.proof)))

        delete cfragJson.proof
        delete parse.proof

        // check rest of cFrag
        assert(_.isEqual(cfragJson, parse))
    })
    it('verify for capsule', function (){
        const utf8Encode = new TextEncoder();

        assert(cFrag.reEncrypt(kfrag, capsule, true, utf8Encode.encode(""), true, not_random).verify_correctness(capsule))
        assert(!cFrag.reEncrypt(kfrag, capsule, true, utf8Encode.encode("WILLFAIL"), true, not_random).verify_correctness(capsule))
    })
})