import assert from 'assert';
import {Capsule} from "../src/pre.js";
import {defaultCurve} from "../src/config.js";
import _ from "lodash"


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
