'use strict'

module.exports = {
  chunk,
  hexToUint8,
  strToUint8,
  Uint8ToHex
}

// Splits a buffer into chunks of a given size
function chunk (buffer: Buffer, chunkSize: number) {
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
function hexToUint8 (hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

// Converts a string into a Uint8Array
function strToUint8 (hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex))
}

function Uint8ToHex (uint8: Uint8Array): string {
  return Buffer.from(uint8).toString('hex')
}