'use strict'

// Splits a buffer into chunks of a given size
exports.chunk = (buffer: Buffer, chunkSize: number) => {
  if (!Buffer.isBuffer(buffer)) throw new Error('Buffer is required')

  let result = [],
    i = 0,
    len = buffer.length

  while (i < len) {
    // If it does not equally divide then set last to whatever remains
    result.push(buffer.slice(i, Math.min((i += chunkSize), len)))
  }

  return result
}

// Converts a hex string into a Uint8Array
exports.hexToUint8 = (hex: string): Uint8Array => {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

// Converts a string into a Uint8Array
exports.strToUint8 = (hex: string): Uint8Array => {
  return Uint8Array.from(Buffer.from(hex))
}

// Converts a Uint8Array to a hex string
exports.Uint8ToHex = (uint8: Uint8Array): string => {
  return Buffer.from(uint8).toString('hex')
}