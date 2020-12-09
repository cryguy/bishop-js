import assert from 'assert';
import {Capsule, encrypt, decrypt} from "../src/pre.js";
import {defaultCurve, EdDSA} from "../src/config.js";
import _ from "lodash"
import {cFrag, kFrag} from "../src/key_fragments.js";
import {fromHexString, toHexString} from "../src/utils.js";


describe('Capsule', function() {
    describe('Deserialization works the same as java', function() {
        var capsule = Capsule.fromJson("{\"hash\":\"8AL0GvAKokeY4CswtdHWYbnXDKaMLwnEoZZ0q5rKYfE\u003d\",\"point_e\":\"AxZpUNwkyXc6ZBQ6YfBYlko/W3OYvBeBKEqSPBKu0R9L\",\"point_v\":\"AxBlaTALB5+hA/T+5u7nHigwv+GWvNaFeHmfH1FtQHGS\",\"signature\":\"CgwehqZKWrqovo5L8EAt+yhH9fIWZ3eVnLZZ2T/GpuU\u003d\"}\n", defaultCurve)
        it('capsule from json works the same as java', function() {
            assert(_.isEqual(JSON.parse(capsule.asJson()), JSON.parse("{\"hash\":\"8AL0GvAKokeY4CswtdHWYbnXDKaMLwnEoZZ0q5rKYfE\u003d\",\"point_e\":\"AxZpUNwkyXc6ZBQ6YfBYlko/W3OYvBeBKEqSPBKu0R9L\",\"point_v\":\"AxBlaTALB5+hA/T+5u7nHigwv+GWvNaFeHmfH1FtQHGS\",\"signature\":\"CgwehqZKWrqovo5L8EAt+yhH9fIWZ3eVnLZZ2T/GpuU\u003d\"}")))
        })
        it('capsule verification works the same as java', function() {
            assert(!capsule.notValid())
        })
    })
})

describe('Umbral Encryption and Decryption works', function () {
    it('encryption decryption', function () {
        const plaintext = Buffer.from("Hello World!")
        //console.log("PLAINTEXT " + plaintext)
        const alice = defaultCurve.keyFromPrivate("a4c620c5a815c3bc0196098f23e59202113b49a19de9008bc6a7f3296b52283");
        const bob = defaultCurve.keyFromPrivate("daf0e008eba2a042895f1407cd088016075bef72233560f47f3e8ed807fc306");
        const alice_ed = EdDSA.keyFromSecret("88AB52BA555F47CD5BE569F6C6AE0CE5DF9B98D07AB84E7403F6BC3037DDA577");

        // const js = "{\"hash\":\"tMLv7gc0o4yRu/kucUOa5RYhKw+KjqT6rShKgHArH0A\u003d\",\"point_e\":\"AyvYhkDa8petg03t92ZDK9aWrhpO4JWgjwwllaKSuyrI\",\"point_v\":\"AkB/n7NcxkdjaC7BX/m2We0nflWUhm5uveV8vcAvH2U5\",\"signature\":\"AMpw3p0DyQZTBQKyZd2aAfWhtGPpXbeq2ChqrNl01uU\u003d\"}\n"
        // const capsule = Capsule.fromJson(js, defaultCurve.curve)

        //
        // let kf = "{\"bn_key\":\"Aa0JOpf13Fkd1qdLrQx3ow7DzKWgK3dvsNWpWkiAnf4\u003d\",\"identifier\":\"K4BlC7bEIFF8DBpvOsGLnS7wKxW88n0ZMKr465+LqYM\u003d\",\"key_in_signature\":\"Aw\u003d\u003d\",\"point_commitment\":\"AxdRLeF02qhe+9lsL5lrKR3zRU9Ph8nC+GEEWtbeEuOG\",\"point_precursor\":\"AyJLN5SDVO95fTocrZ6yOxuhkDWMJ6MZZJAfguorXfVO\",\"signature_for_bob\":\"tqltRIKDOSY6Pk3YCAwkQmFcAvggba4cZRgFoFpqeosLUlAkIoU4m3UuJZ8ieLO3uwkxGkEkKHyQcg8u98R3DA\u003d\u003d\",\"signature_for_proxy\":\"kve1uQ87kx5dBBV6tn1xAugT0vusx9rqbX+376pzSaf7MFzYrP9mC6lCtgvoc/6QdLVLiyqMhRcUN0jIOs9YDg\u003d\u003d\"}\n"
        //
        // kf = kFrag.fromJson(kf)
        //
        const capsule_cipher = encrypt(alice.getPublic(), plaintext)

        const capsule = capsule_cipher.capsule;

        capsule.setCorrectnessKey(alice.getPublic(), bob.getPublic(),alice_ed.getPublic())

        const kfrags = kFrag.generate_kfrags(alice, bob.getPublic(), 3,5, alice_ed, true,true, null)

        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[0],capsule,true,null,true));
        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[1],capsule,true,null,true));
        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[2],capsule,true,null,true));
        //

        //console.log(kfrag.identifier)
        //let cfj = JSON.parse("{\"e1\":\"AlCdCREG/AL2eO/TEpMqeckKrKh6qGsqEmDRLh4k1oM5\",\"kfrag_id\":\"XKpygRLyYeAvx9nqaWXC5pPFX1UURkVuUw+k38IWoq4\u003d\",\"precursor\":\"AlQ9ax48ziyfsJS9lwWJ6sgx8zSsHCqiu+bZoSlY/RkA\",\"v1\":\"AlV2jdCi5gC4PsYRVKWD+z1L+Bv1+p9PKjnuAglJbITS\"}\n")

        //cfj.proof = "{\"commitment\":\"A1AIXuZoXK5HuislBwWfbzI/hCQnjpEx0bGKMUA7YP43\",\"e2\":\"Az4eYcgfsyySP2Zfi1dKoMGjF0me0Q8vf2JNMlwBMNjr\",\"pok\":\"AmezCwKqfx968ZmmWRjvXCSMO584p78ND/sw/1on6mwJ\",\"sig_key\":\"AnBOmkmgRZI8AqNJN2s0KFu8rQ+JsnMnaxqREHQj65Y\u003d\",\"signature\":\"NDNEwR4kQGZh3QpvAZ6IsfOqy7K5S12P/lz5SHGU57n1HZglyEwtIDgZCuMPbrJ6ufWq8VJynrldISR3Pan+Ag\u003d\u003d\",\"v2\":\"A1Z2TXPMDJPVv6SwKXE+oe8AxkkOH/RgtNuRQcXfKmA5\"}\n"
        //console.log(JSON.stringify(cfj))
        //const cfrag = cFrag.fromJson(JSON.stringify(cfj))

        //console.log(cfrag.kfrag_id)




        //console.log(cfrag)
        //console.log(toHexString(decrypt(fromHexString("951492863FA64B0911D1334997093545034C6E9A6906D4BA1382B72D354F0134AB3CACDC839C2618"), capsule, bob, true)))


        //
        // console.log("CAPSULE " + capsule.asJson())
        // const ciphertext = capsule_cipher.ciphertext;
        // console.log("CIPHERTEXT " + toHexString(ciphertext))
        // const kfrags = kFrag.generate_kfrags(alice, bob.getPublic(), 1,1, alice_ed, true,true, null)
        // console.log(kfrags[0].asJson())
        // capsule.setCorrectnessKey(alice.getPublic(),bob.getPublic(), alice_ed.getPublic())
        // kfrags.forEach(value => {
        //     capsule.AttachedCfrags.push(cFrag.reEncrypt(value, capsule, true, null, true));
        // })
        assert(toHexString(decrypt(capsule_cipher.ciphertext, capsule,bob)), "48656C6C6F20576F726C6421")
        //console.log(toHexString(decrypt(fromHexString("D58FA6FA41FD3023311F0267E62AA39ABEA660BE149C521368489DB64BE055D6B07F2EDFEB5A95C0"), capsule,bob))) // 48656C6C6F20576F726C6421 == Hello World!
        //assert(!plaintext.compare()) // equal
    })

})
