import * as Crypto from 'crypto';
import Hashids from 'hashids';
import { decodeBuffer, encodeBuffer } from './base64';
import { IDMailformedError } from './IDMailformedError';

// Randomly generated string for using as salt for type name hashing
const typeKeySalt = '2773246209f10fc3381f5ca55c67dac5486e27ff1ce3f698b1859008fe0053e3';
// Randomly generated string for using as salt for encryption key derivation
const encryptionKeySalt = 'a638abdfb70e39476858543b3216b23ca5d1ac773eaf797a130639a76081c3aa';
// Randomly generated string for using as salt for encryption iv derivation
const encryptionIvSalt = '4c66c9e004fb48caaa38aa72dc749f946d0ccfe4edf8f993776388b6349a2895';
// Randomly generated string for using as salt for hmac secret derivation
const hmacSecretSalt = 'c15c63b812d78d8e368f2d702e43dd885f3bcf0e446203951b12cf3ab9715716';
// Randomly generated string for using as salt for hashds salt derivation
const hashidsSalt = '11705939e5cad46fa04a6fc838a3fa25c0f50439c946101199b8506ff73a2ebe';

// Truncated size of HMAC
const HMAC_LENGTH = 8;
// Expected minimum Key Length
const MIN_KEY_LENGTH = 13;

type SecIDv2ValueTypeName = 'number' | 'string';
type SecIDv2ValueType = number | string;

const NUMBER_VERSION = 1;
const STRING_VERSION = 2;

export type SecIDStyle = 'hex' | 'base64' | 'hashids';

function decodeStyle(value: string, style: SecIDStyle, hashids: Hashids) {
    if (style === 'hex') {
        return Buffer.from(value, 'hex');
    } else if (style === 'base64') {
        return decodeBuffer(value);
    } else {
        let hid = hashids.decodeHex(value);
        return Buffer.from(hid, 'hex');
    }
}

function encodeStyle(value: Buffer, style: SecIDStyle, hashids: Hashids) {
    if (style === 'hex') {
        return value.toString('hex');
    } else if (style === 'base64') {
        return encodeBuffer(value);
    } else {
        return hashids.encodeHex(value.toString('hex'));
    }
}

function encodeNumberIdBody(value: SecIDv2ValueType, typeId: number) {
    // Preflight check
    if (typeof value !== 'number') {
        throw new IDMailformedError('Id value and valueType mismatch, got: ' + value + ', ' + (typeof value));
    }
    if (value < 0) {
        throw new IDMailformedError('Ids can\'t be negative!');
    }
    if (!Number.isInteger(value)) {
        throw new IDMailformedError('Ids can\'t be float numbers!');
    }
    if (value > 2147483647) {
        throw new IDMailformedError('Ids can\'t be bigger than 2147483647. Got: ' + value);
    }

    let buf = Buffer.alloc(7);
    // Write version
    buf.writeInt8(NUMBER_VERSION, 0);
    // Write type id
    buf.writeUInt16BE(typeId, 1);
    // Write id
    buf.writeInt32BE(value, 3);

    return buf;
}

function encodeStringIdBody(value: SecIDv2ValueType, typeId: number) {
    // Preflight check
    if (typeof value !== 'string') {
        throw new IDMailformedError('Id value and valueType mismatch');
    }
    if (value.length > 65535) {
        throw new IDMailformedError('Ids string value length can\'t be bigger than 65535. Got: ' + value.length);
    }

    let stringBuf = Buffer.from(value, 'utf-8');
    let buf = Buffer.alloc(5);
    // Write version
    buf.writeInt8(STRING_VERSION, 0);
    // Write type id
    buf.writeUInt16BE(typeId, 1);
    // Write string length
    buf.writeUInt16BE(stringBuf.byteLength, 3);
    // Write string
    buf = Buffer.concat([buf, stringBuf]);

    return buf;
}

function encrypt(value: SecIDv2ValueType, valueType: SecIDv2ValueTypeName, typeId: number, encryptionKey: Buffer, encryptionIv: Buffer, hmacKey: Buffer) {
    let buf: Buffer;

    if (valueType === 'number') {
        buf = encodeNumberIdBody(value, typeId);
    } else if (valueType === 'string') {
        buf = encodeStringIdBody(value, typeId);
    } else {
        throw new IDMailformedError('Unknown id value type ' + valueType);
    }

    // Encrypt
    let cipher = Crypto.createCipheriv('aes-128-ctr', encryptionKey, encryptionIv);
    let res = cipher.update(buf);
    res = Buffer.concat([res, cipher.final()]);

    // then MAC
    let hmac = Crypto.createHmac('sha256', hmacKey).update(res).digest().slice(0, HMAC_LENGTH);
    res = Buffer.concat([res, hmac]);

    return res;
}

function decrypt(valuestr: string, value: Buffer, type: number | Set<number>, encryptionKey: Buffer, encryptionIv: Buffer, hmacKey: Buffer) {
    let decipher = Crypto.createDecipheriv('aes-128-ctr', encryptionKey, encryptionIv);
    let dataLen = value.byteLength - 8;
    let sourceContent = value.slice(0, dataLen);
    let sourceHmac = value.slice(dataLen, dataLen + 8);

    // Decryption
    let decoded = decipher.update(sourceContent);
    decoded = Buffer.concat([decoded, decipher.final()]);

    // Hmac
    let hmacActual = Crypto.createHmac('sha256', hmacKey).update(sourceContent).digest().slice(0, HMAC_LENGTH);

    // For consant time read evertyhing before checking
    if (hmacActual.byteLength !== sourceHmac.byteLength) {
        if (hmacActual.length > sourceHmac.length) {
            sourceHmac = Buffer.concat([sourceHmac, Buffer.alloc(hmacActual.length - sourceHmac.length)]);
        } else {
            hmacActual = Buffer.concat([hmacActual, Buffer.alloc(sourceHmac.length - hmacActual.length)]);
        }
    }
    let hmacCorrect = Crypto.timingSafeEqual(hmacActual, sourceHmac);
    let valueVersion = decoded.readUInt8(0);
    let valueTypeId = decoded.readUInt16BE(1);
    let correctValueTypeId = false;
    let valueRes: SecIDv2ValueType | undefined;

    if (valueVersion === NUMBER_VERSION) {
        correctValueTypeId = true;
        valueRes = decoded.readUInt32BE(3);
    } else if (valueVersion === STRING_VERSION) {
        correctValueTypeId = true;
        let stringLen = decoded.readUInt16BE(3);
        valueRes = decoded.slice(5, 5 + stringLen).toString('utf-8');
    }

    // Constant time integrity check
    let correctVersion = valueVersion === NUMBER_VERSION || valueVersion === STRING_VERSION;
    let correctType = false;
    if (typeof type === 'number') {
        correctType = valueTypeId === type;
    } else {
        correctType = type.has(valueTypeId);
    }
    if (correctType && correctVersion && hmacCorrect && correctValueTypeId && valueRes !== undefined) {
        return { id: valueRes, type: valueTypeId };
    }
    throw new IDMailformedError('Invalid id: ' + valuestr);
}

export class SecID<T extends SecIDv2ValueType = any> {
    public readonly typeName: string;
    public readonly typeId: number;
    private readonly valueType: SecIDv2ValueTypeName;
    private readonly encryptionKey: Buffer;
    private readonly encryptionIv: Buffer;
    private readonly hmacKey: Buffer;
    private readonly style: SecIDStyle;
    private readonly hashids: Hashids;

    constructor(
        typeName: string,
        typeId: number,
        valueType: SecIDv2ValueTypeName,
        encryptionKey: Buffer,
        encryptionIv: Buffer,
        hmacKey: Buffer,
        style: SecIDStyle,
        hashids: Hashids
    ) {
        this.typeName = typeName;
        this.typeId = typeId;
        this.valueType = valueType;
        this.encryptionKey = encryptionKey;
        this.encryptionIv = encryptionIv;
        this.hmacKey = hmacKey;
        this.style = style;
        this.hashids = hashids;
    }

    serialize(value: T) {
        let encrypted = encrypt(value, this.valueType, this.typeId, this.encryptionKey, this.encryptionIv, this.hmacKey);
        return encodeStyle(encrypted, this.style, this.hashids);
    }

    parse(value: string): T {
        // Decode style
        let source = decodeStyle(value, this.style, this.hashids);
        if (source.length < MIN_KEY_LENGTH) {
            throw new IDMailformedError('Invalid id');
        }
        return decrypt(value, source, this.typeId, this.encryptionKey, this.encryptionIv, this.hmacKey).id as T;
    }
}

export class SecIDFactory {
    private readonly typeSalt: string;
    private readonly encryptionKey: Buffer;
    private readonly encryptionIv: Buffer;
    private readonly hmacKey: Buffer;
    private readonly style: SecIDStyle;
    private readonly hashids: Hashids;
    private knownTypes = new Set<number>();
    private knownSecIDS = new Map<number, SecID>();

    constructor(secret: string, style: SecIDStyle = 'hashids') {
        this.style = style;
        this.typeSalt = Crypto.pbkdf2Sync(secret, typeKeySalt, 100000, 32, 'sha512').toString('hex');
        this.encryptionKey = Crypto.pbkdf2Sync(secret, encryptionKeySalt, 100000, 16, 'sha512');
        this.encryptionIv = Crypto.pbkdf2Sync(secret, encryptionIvSalt, 100000, 16, 'sha512');
        this.hmacKey = Crypto.pbkdf2Sync(secret, hmacSecretSalt, 100000, 64, 'sha512');
        this.hashids = new Hashids(Crypto.pbkdf2Sync(secret, hashidsSalt, 100000, 32, 'sha512').toString('hex'));
    }

    resolve(value: string) {
        let source = decodeStyle(value, this.style, this.hashids);
        if (source.length < MIN_KEY_LENGTH) {
            throw new IDMailformedError('Invalid id');
        }
        let res = decrypt(value, source, this.knownTypes, this.encryptionKey, this.encryptionIv, this.hmacKey);
        return {
            id: res.id,
            type: this.knownSecIDS.get(res.type)!!
        };
    }

    createId(type: string) {
        return this.doCreateId<number>(type, 'number');
    }

    createStringId(type: string) {
        return this.doCreateId<string>(type, 'string');
    }

    private doCreateId<T extends SecIDv2ValueType>(type: string, valueType: SecIDv2ValueTypeName) {
        // Hashing of type name
        // We don't need to make this hash secure.
        // Just to "compress" and use hash instead of a full name.

        // Using simple hash: sha1
        let hash = Crypto.createHash('sha1');
        // Append type salt to avoid duplicates in different factory instances (with different secret).
        hash.update(this.typeSalt, 'utf8');
        // Append type as is
        hash.update(type.toLowerCase(), 'utf8');
        // Read first two bytes of hash
        let res = hash.digest();
        let typeId = res.readUInt16BE(0);

        // Check for uniques since there could be collisions
        if (this.knownTypes.has(typeId)) {
            throw Error('SecID type collision for "' + type + '", please try to use different name.');
        }
        this.knownTypes.add(typeId);

        // Build SecID instance
        let id = new SecID<T>(type, typeId, valueType, this.encryptionKey, this.encryptionIv, this.hmacKey, this.style, this.hashids);
        this.knownSecIDS.set(typeId, id);
        return id;
    }
}
