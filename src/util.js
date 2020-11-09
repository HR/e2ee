'use strict';
// Splits a buffer into chunks of a given size
exports.chunk = function (buffer, chunkSize) {
    if (!Buffer.isBuffer(buffer))
        throw new Error('Buffer is required');
    var result = [], i = 0, len = buffer.length;
    while (i < len) {
        // If it does not equally divide then set last to whatever remains
        result.push(buffer.slice(i, Math.min((i += chunkSize), len)));
    }
    return result;
};
// Converts a hex string into a Uint8Array
exports.hexToUint8 = function (hex) {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
};
// Converts a string into a Uint8Array
exports.strToUint8 = function (hex) {
    return Uint8Array.from(Buffer.from(hex));
};
exports.Uint8ToHex = function (uint8) {
    return Buffer.from(uint8).toString('hex');
};
