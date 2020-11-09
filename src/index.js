"use strict";
/// <reference types="node" />
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var scrypto = require('crypto'), fs = require('fs'), hkdf = require('futoin-hkdf'), 
// TODO: Replace with scrypto.diffieHellman once nodejs#26626 lands on v12 LTS
_a = require('tweetnacl'), box = _a.box, sign = _a.sign, _b = require('./util'), chunk = _b.chunk, hexToUint8 = _b.hexToUint8, strToUint8 = _b.strToUint8, Uint8ToHex = _b.Uint8ToHex, STORE_KEY = 'publicKey', CIPHER = 'aes-256-cbc', RATCHET_KEYS_LEN = 64, RATCHET_KEYS_HASH = 'SHA-256', MESSAGE_KEY_LEN = 80, MESSAGE_CHUNK_LEN = 32, MESSAGE_KEY_SEED = 1, // 0x01
CHAIN_KEY_SEED = 2, // 0x02
RACHET_MESSAGE_COUNT = 10; // Rachet after this no of messages sent
module.exports = /** @class */ (function () {
    function E2EE(options) {
        this._sessions = {};
        this._store = options.store || new Map();
        this._getSecretIdentity = options.getSecretIdentity || this._getSecretIdentityDef;
        this._setSecretIdentity = options.setSecretIdentity || this._setSecretIdentityDef;
        // Bindings
        this.init = this.init.bind(this);
    }
    // Default implementations
    E2EE.prototype._getSecretIdentityDef = function (publicKey) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._store.get(publicKey)];
            });
        });
    };
    E2EE.prototype._setSecretIdentityDef = function (publicKey, secretKey) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._store.set(publicKey, secretKey)];
            });
        });
    };
    E2EE.prototype.init = function () {
        return __awaiter(this, void 0, void 0, function () {
            var publicKey, secretKey, _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        publicKey = this._store.get(STORE_KEY, false);
                        _a = publicKey;
                        if (!_a) return [3 /*break*/, 2];
                        return [4 /*yield*/, this._getSecretIdentity(publicKey)];
                    case 1:
                        _a = (_b.sent());
                        _b.label = 2;
                    case 2:
                        secretKey = _a;
                        // Restore keys if they exist
                        if (publicKey && secretKey) {
                            this._identity = { publicKey: publicKey, secretKey: hexToUint8(secretKey) };
                            return [2 /*return*/, this._identity];
                        }
                        // Generate new ones otherwise
                        return [4 /*yield*/, this._generateIdentityKeyPair()];
                    case 3:
                        // Generate new ones otherwise
                        _b.sent();
                        return [2 /*return*/, this._identity];
                }
            });
        });
    };
    E2EE.prototype._saveIdentity = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this._store.set(STORE_KEY, this._identity.publicKey);
                        // Save the private key in the OS's keychain under public key
                        return [4 /*yield*/, this._setSecretIdentity(this._identity.publicKey, Uint8ToHex(this._identity.secretKey))];
                    case 1:
                        // Save the private key in the OS's keychain under public key
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    // Generates a new Curve25519 key pair
    E2EE.prototype._generateIdentityKeyPair = function () {
        return __awaiter(this, void 0, void 0, function () {
            var keyPair;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        keyPair = sign.keyPair();
                        // Encode in hex for easier handling
                        keyPair.publicKey = Uint8ToHex(keyPair.publicKey);
                        this._identity = keyPair;
                        return [4 /*yield*/, this._saveIdentity()];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    E2EE.prototype.sign = function (data) {
        return Uint8ToHex(sign.detached(strToUint8(data), this._identity.secretKey));
    };
    E2EE.prototype.verify = function (publicKey, data, signature) {
        return sign.detached.verify(strToUint8(data), hexToUint8(signature), hexToUint8(publicKey));
    };
    // Generates a server connection authentication request
    E2EE.prototype.generateAuthRequest = function () {
        var timestamp = new Date().toISOString();
        var signature = this.sign(timestamp);
        var publicKey = this._identity.publicKey;
        return { publicKey: publicKey, timestamp: timestamp, signature: signature };
    };
    // Returns a hash digest of the given data
    E2EE.prototype.hash = function (data, enc, alg) {
        if (enc === void 0) { enc = 'hex'; }
        if (alg === void 0) { alg = 'sha256'; }
        return scrypto.createHash(alg).update(data).digest(enc);
    };
    // Returns a hash digest of the given file
    E2EE.prototype.hashFile = function (path, enc, alg) {
        if (enc === void 0) { enc = 'hex'; }
        if (alg === void 0) { alg = 'sha256'; }
        return new Promise(function (resolve, reject) {
            return fs
                .createReadStream(path)
                .on('error', reject)
                .pipe(scrypto.createHash(alg).setEncoding(enc))
                .once('finish', function () {
                resolve(this.read());
            });
        });
    };
    // Hash Key Derivation Function (based on HMAC)
    E2EE.prototype._HKDF = function (input, salt, info, length) {
        if (length === void 0) { length = RATCHET_KEYS_LEN; }
        // input = input instanceof Uint8Array ? Buffer.from(input) : input
        // salt = salt instanceof Uint8Array ? Buffer.from(salt) : salt
        return hkdf(input, length, {
            salt: salt,
            info: info,
            hash: RATCHET_KEYS_HASH,
        });
    };
    // Hash-based Message Authentication Code
    E2EE.prototype._HMAC = function (key, data, enc, algo) {
        if (enc === void 0) { enc = 'utf8'; }
        if (algo === void 0) { algo = 'sha256'; }
        return scrypto.createHmac(algo, key).update(data).digest(enc);
    };
    // Generates a new Curve25519 key pair
    E2EE.prototype._generateRatchetKeyPair = function () {
        var keyPair = box.keyPair();
        // Encode in hex for easier handling
        keyPair.publicKey = Buffer.from(keyPair.publicKey).toString('hex');
        return keyPair;
    };
    // Initialises an end-to-end encryption session
    E2EE.prototype.initSession = function (id) {
        return __awaiter(this, void 0, void 0, function () {
            var _a, publicKey, secretKey, timestamp, signature;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _a = this._generateRatchetKeyPair(), publicKey = _a.publicKey, secretKey = _a.secretKey;
                        // Initialise session object
                        this._sessions[id] = {
                            currentRatchet: {
                                sendingKeys: {
                                    publicKey: publicKey,
                                    secretKey: secretKey,
                                },
                                previousCounter: 0,
                            },
                            sending: {},
                            receiving: {},
                        };
                        timestamp = new Date().toISOString();
                        return [4 /*yield*/, this.sign(publicKey + timestamp)];
                    case 1:
                        signature = _b.sent();
                        console.log('Initialised new session', this._sessions[id]);
                        return [2 /*return*/, { publicKey: publicKey, timestamp: timestamp, signature: signature }];
                }
            });
        });
    };
    // Starts the session
    E2EE.prototype.startSession = function (id, keyMessage) {
        return __awaiter(this, void 0, void 0, function () {
            var publicKey, timestamp, signature, sigValid, ratchet, secretKey, rootKey;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        publicKey = keyMessage.publicKey, timestamp = keyMessage.timestamp, signature = keyMessage.signature;
                        return [4 /*yield*/, this.verify(id, publicKey + timestamp, signature)
                            // Ignore if new encryption session if signature not valid
                        ];
                    case 1:
                        sigValid = _a.sent();
                        // Ignore if new encryption session if signature not valid
                        if (!sigValid)
                            return [2 /*return*/, console.log('PubKey sig invalid', publicKey)];
                        ratchet = this._sessions[id].currentRatchet;
                        secretKey = ratchet.sendingKeys.secretKey;
                        ratchet.receivingKey = publicKey;
                        rootKey = this._calcRatchetKeys('E2eeSecret', secretKey, publicKey)[0];
                        ratchet.rootKey = rootKey;
                        console.log('Initialised Session', rootKey.toString('hex'), this._sessions[id]);
                        return [2 /*return*/];
                }
            });
        });
    };
    // Calculates the ratchet keys (root and chain key)
    E2EE.prototype._calcRatchetKeys = function (oldRootKey, sendingSecretKey, receivingKey) {
        // Convert receivingKey to a Uint8Array if it isn't already
        if (typeof receivingKey === 'string')
            receivingKey = hexToUint8(receivingKey);
        // Derive shared ephemeral secret
        var sharedSecret = box.before(receivingKey, sendingSecretKey);
        // Derive the new ratchet keys
        var ratchetKeys = this._HKDF(sharedSecret, oldRootKey, 'E2eeRatchet');
        console.log('Derived ratchet keys', ratchetKeys.toString('hex'));
        // Chunk ratchetKeys output into its parts: root key and chain key
        return chunk(ratchetKeys, RATCHET_KEYS_LEN / 2);
    };
    // Calculates the next receiving or sending ratchet
    E2EE.prototype._calcRatchet = function (session, sending, receivingKey) {
        var ratchet = session.currentRatchet;
        var ratchetChains, publicKey, previousChain;
        if (sending) {
            ratchetChains = session.sending;
            previousChain = ratchetChains[ratchet.sendingKeys.publicKey];
            // Replace ephemeral ratchet sending keys with new ones
            ratchet.sendingKeys = this._generateRatchetKeyPair();
            publicKey = ratchet.sendingKeys.publicKey;
            console.log('New sending keys generated', publicKey);
        }
        else {
            // TODO: Check counters to pre-compute skipped keys
            ratchetChains = session.receiving;
            previousChain = ratchetChains[ratchet.receivingKey];
            publicKey = ratchet.receivingKey = receivingKey;
        }
        if (previousChain) {
            // Update the previousCounter with the previous chain counter
            ratchet.previousCounter = previousChain.chain.counter;
        }
        // Derive new ratchet keys
        var _a = this._calcRatchetKeys(ratchet.rootKey, ratchet.sendingKeys.secretKey, ratchet.receivingKey), rootKey = _a[0], chainKey = _a[1];
        // Update root key
        ratchet.rootKey = rootKey;
        // Initialise new chain
        ratchetChains[publicKey] = {
            messageKeys: {},
            chain: {
                counter: -1,
                key: chainKey,
            },
        };
        return ratchetChains[publicKey];
    };
    // Calculates the next message key for the ratchet and updates it
    // TODO: Try to get messagekey with message counter otherwise calculate all
    // message keys up to it and return it (instead of pre-comp on ratchet)
    E2EE.prototype._calcMessageKey = function (ratchet) {
        var chain = ratchet.chain;
        // Calculate next message key
        var messageKey = this._HMAC(chain.key, Buffer.alloc(1, MESSAGE_KEY_SEED));
        // Calculate next ratchet chain key
        chain.key = this._HMAC(chain.key, Buffer.alloc(1, CHAIN_KEY_SEED));
        // Increment the chain counter
        chain.counter++;
        // Save the message key
        ratchet.messageKeys[chain.counter] = messageKey;
        console.log('Calculated next messageKey', ratchet);
        // Derive encryption key, mac key and iv
        return chunk(this._HKDF(messageKey, 'E2eeCrypt', null, MESSAGE_KEY_LEN), MESSAGE_CHUNK_LEN);
    };
    // Encrypts a message
    E2EE.prototype.encrypt = function (id, message, returnCipher) {
        if (message === void 0) { message = {}; }
        if (returnCipher === void 0) { returnCipher = false; }
        return __awaiter(this, void 0, void 0, function () {
            var session, ratchet, sendingChain, shouldRatchet, previousCounter, publicKey, _a, encryptKey, hmac, iv, counter, msgJson, msgCipher, packet, _b, res;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        session = this._sessions[id];
                        ratchet = session.currentRatchet;
                        sendingChain = session.sending[ratchet.sendingKeys.publicKey];
                        shouldRatchet = sendingChain && sendingChain.chain.counter >= RACHET_MESSAGE_COUNT;
                        if (!sendingChain || shouldRatchet) {
                            sendingChain = this._calcRatchet(session, true);
                            console.log('Calculated new sending ratchet', session);
                        }
                        previousCounter = ratchet.previousCounter;
                        publicKey = ratchet.sendingKeys.publicKey;
                        _a = this._calcMessageKey(sendingChain), encryptKey = _a[0], hmac = _a[1], iv = _a[2];
                        console.log('Calculated encryption creds', encryptKey.toString('hex'), iv.toString('hex'));
                        counter = sendingChain.chain.counter;
                        // Encrypt message
                        if (message) {
                            msgJson = JSON.stringify(message);
                            msgCipher = scrypto.createCipheriv(CIPHER, encryptKey, iv);
                            message = msgCipher.update(msgJson, 'utf8', 'hex') + msgCipher.final('hex');
                        }
                        packet = {
                            message: message,
                            publicKey: publicKey,
                            previousCounter: previousCounter,
                            counter: counter,
                        };
                        // Sign message with PGP
                        _b = packet;
                        return [4 /*yield*/, this.sign(JSON.stringify(packet))];
                    case 1:
                        // Sign message with PGP
                        _b.signature = _c.sent();
                        console.log('Encrypted', packet);
                        res = { packet: packet, cipher: null };
                        if (returnCipher)
                            res.cipher = scrypto.createCipheriv(CIPHER, encryptKey, iv);
                        return [2 /*return*/, res];
                }
            });
        });
    };
    // Decrypts a message
    E2EE.prototype.decrypt = function (id, packet, returnDecipher) {
        if (returnDecipher === void 0) { returnDecipher = false; }
        return __awaiter(this, void 0, void 0, function () {
            var signature, packetBody, sigValid, publicKey, counter, previousCounter, message, session, receivingChain, _a, decryptKey, hmac, iv, msgDecipher, res;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        signature = packet.signature, packetBody = __rest(packet, ["signature"]);
                        return [4 /*yield*/, this.verify(id, JSON.stringify(packetBody), signature)
                            // Ignore message if signature invalid
                        ];
                    case 1:
                        sigValid = _b.sent();
                        // Ignore message if signature invalid
                        if (!sigValid) {
                            throw new Error('Message signature invalid!');
                        }
                        publicKey = packetBody.publicKey, counter = packetBody.counter, previousCounter = packetBody.previousCounter;
                        message = packetBody.message;
                        session = this._sessions[id];
                        receivingChain = session.receiving[publicKey];
                        if (!receivingChain) {
                            // Receiving ratchet for key does not exist so create one
                            receivingChain = this._calcRatchet(session, false, publicKey);
                            console.log('Calculated new receiving ratchet', receivingChain);
                        }
                        _a = this._calcMessageKey(receivingChain), decryptKey = _a[0], hmac = _a[1], iv = _a[2];
                        console.log('Calculated decryption creds', decryptKey.toString('hex'), iv.toString('hex'));
                        // Decrypt the message contents
                        if (message) {
                            msgDecipher = scrypto.createDecipheriv(CIPHER, decryptKey, iv);
                            message = msgDecipher.update(message, 'hex', 'utf8') + msgDecipher.final('utf8');
                            message = JSON.parse(message);
                            console.log('--> Decrypted message', message);
                        }
                        res = { message: message, decipher: null };
                        if (returnDecipher)
                            res.decipher = scrypto.createDecipheriv(CIPHER, decryptKey, iv);
                        return [2 /*return*/, res];
                }
            });
        });
    };
    return E2EE;
}());
