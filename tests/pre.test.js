import assert from 'assert';
import {Capsule, encrypt, decrypt} from "../src/pre.js";
import {defaultCurve, EdDSA} from "../src/config.js";
import _ from "lodash"
import {cFrag, kFrag} from "../src/key_fragments.js";
import {toHexString} from "../src/utils.js";


describe('Capsule', function() {
    describe('Deserialization works the same as java', function () {
        var capsule = Capsule.fromJson("{\"hash\":\"8AL0GvAKokeY4CswtdHWYbnXDKaMLwnEoZZ0q5rKYfE\u003d\",\"point_e\":\"AxZpUNwkyXc6ZBQ6YfBYlko/W3OYvBeBKEqSPBKu0R9L\",\"point_v\":\"AxBlaTALB5+hA/T+5u7nHigwv+GWvNaFeHmfH1FtQHGS\",\"signature\":\"CgwehqZKWrqovo5L8EAt+yhH9fIWZ3eVnLZZ2T/GpuU\u003d\"}\n", defaultCurve)
        it('capsule from json works the same as java', function () {
            assert(_.isEqual(JSON.parse(capsule.asJson()), JSON.parse("{\"hash\":\"8AL0GvAKokeY4CswtdHWYbnXDKaMLwnEoZZ0q5rKYfE\u003d\",\"point_e\":\"AxZpUNwkyXc6ZBQ6YfBYlko/W3OYvBeBKEqSPBKu0R9L\",\"point_v\":\"AxBlaTALB5+hA/T+5u7nHigwv+GWvNaFeHmfH1FtQHGS\",\"signature\":\"CgwehqZKWrqovo5L8EAt+yhH9fIWZ3eVnLZZ2T/GpuU\u003d\"}")))
        })
        it('capsule verification works the same as java', function () {
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
        const alice_ed = EdDSA.keyFromSecret("88AB52BA555F47CD5BE569F6C6AE0CE5DF9B98D07AB84E7403FAAAAA37DDA577");


        const capsule_cipher = encrypt(alice.getPublic(), plaintext)
        console.log(capsule_cipher.ciphertext.length)
        const capsule = capsule_cipher.capsule;

        capsule.setCorrectnessKey(alice.getPublic(), bob.getPublic(),alice_ed.getPublic())

        const kfrags = kFrag.generate_kfrags(alice, bob.getPublic(), 4,5, alice_ed, true,true, null)

        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[0],capsule,true,null,true));
        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[1],capsule,true,null,true));
        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[2],capsule,true,null,true));
        capsule.AttachedCfrags.push(cFrag.reEncrypt(kfrags[3],capsule,true,null,true));

        assert.equal(toHexString(decrypt(capsule_cipher.ciphertext, capsule,bob)), "48656C6C6F20576F726C6421")

    })

})
