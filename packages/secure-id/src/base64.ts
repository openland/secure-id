function unescape(str: string) {
    return (str + '==='.slice((str.length + 3) % 4))
        .replace(/-/g, '+')
        .replace(/_/g, '/');
}

function escape(str: string) {
    return str.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

export function encodeBuffer(buffer: Buffer) {
    return escape(buffer.toString('base64'));
}

export function decodeBuffer(str: string) {
    return Buffer.from(unescape(str), 'base64');
}