import base64js from 'base64-js'

function toHexString (byteArray) {
    return Array.prototype.map.call(byteArray, x => ('00' + x.toString(16)).slice(-2)).join('').toUpperCase()
}
// function toHexString(byteArray) {
//     return Array.from(byteArray, function(byte) {
//         return ('0' + (byte & 0xFF).toString(16)).slice(-2);
//     }).join('')
// }
// function toHexString(byteArray) {
//     var s = '0x';
//     byteArray.forEach(function(byte) {
//         s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
//     });
//     return s;
// }

// function toHexString(byteArray) {
//     return byteArray.reduce((output, elem) =>
//             (output + ('0' + elem.toString(16)).slice(-2)),
//         '');
// }

// function byteToHex(byte) {
//     // convert the possibly signed byte (-128 to 127) to an unsigned byte (0 to 255).
//     // if you know, that you only deal with unsigned bytes (Uint8Array), you can omit this line
//     const unsignedByte = byte & 0xff;
//
//     // If the number can be represented with only 4 bits (0-15),
//     // the hexadecimal representation of this number is only one char (0-9, a-f).
//     if (unsignedByte < 16) {
//         return '0' + unsignedByte.toString(16);
//     } else {
//         return unsignedByte.toString(16);
//     }
// }
//
// // bytes is an typed array (Int8Array or Uint8Array)
// function toHexString(bytes) {
//     // Since the .map() method is not available for typed arrays,
//     // we will convert the typed array to an array using Array.from().
//     return Array.from(bytes)
//         .map(byte => byteToHex(byte))
//         .join('');
// }

export function base64ToArrayBuffer(signature) {
    var binary_string = atob(signature);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}


function mergeTypedArrays(a, b) {
    // Checks for truthy values on both arrays
    if(!a && !b) throw 'Please specify valid arguments for parameters a and b.';

    // Checks for truthy values or empty arrays on each argument
    // to avoid the unnecessary construction of a new array and
    // the type comparison
    if(!b || b.length === 0) return a;
    if(!a || a.length === 0) return b;

    // Make sure that both typed arrays are of the same type
    if(Object.prototype.toString.call(a) !== Object.prototype.toString.call(b))
        throw 'The types of the two arguments passed for parameters a and b do not match.';

    const c = new a.constructor(a.length + b.length);

    c.set(a);
    c.set(b, a.length);

    return c;
}


function fromHexString (str) {
    var a = []
    for (var i = 0, len = str.length; i < len; i += 2) {
        a.push(parseInt(str.substr(i, 2), 16))
    }
    return new Uint8Array(a)
}

function toBase64 (bytes) {
    return base64js.fromByteArray(bytes)
}

function fromBase64 (base64) {
    return base64js.toByteArray(base64)
}

export { toHexString, fromHexString, toBase64, fromBase64, mergeTypedArrays }