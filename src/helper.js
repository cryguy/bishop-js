import * as ed from 'noble-ed25519';
const privKey = ed.utils.randomPrivateKey(); // 32-byte Uint8Array or string.
const msgHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
(async () => {
    const publicKey = await ed.getPublicKey(privKey);
    const signature = await ed.sign(msgHash, privKey);
    const isSigned = await ed.verify(signature, msgHash, publicKey);
})();
