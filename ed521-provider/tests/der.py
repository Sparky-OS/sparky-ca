# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Just enough DER (ITU-T X.690) to read and write the test certificates, CRLs and CMS messages."""
import base64

ED521_OID = '1.3.6.1.4.1.44588.2.1'


def read(data, position=0):
    """One TLV at position: (tag, content, whole element, next position)."""
    tag = data[position]
    length = data[position + 1]
    start = position + 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[start:start + count], 'big')
        start += count
    end = start + length
    if end > len(data):
        raise ValueError('truncated DER')
    return tag, data[start:end], data[position:end], end


def children(data):
    result, position = [], 0
    while position < len(data):
        tag, content, whole, position = read(data, position)
        result.append((tag, content, whole))
    return result


def certificate_parts(der, crl=False):
    """(to-be-signed bytes, AlgorithmIdentifier content, raw public key or None, signature bytes)."""
    outer = children(read(der)[1])
    tbs, algorithm, signature = outer
    public = None
    if not crl:
        fields = children(tbs[1])
        offset = 1 if fields[0][0] == 0xa0 else 0
        spki = children(fields[offset + 5][1])
        public = spki[1][1][1:]
    return tbs[2], algorithm[1], public, signature[1][1:]


def length(size):
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


def sequence(*items):
    return tlv(0x30, b''.join(items))


def set_of(*items):
    return tlv(0x31, b''.join(sorted(items)))


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'big', signed=True)
    return tlv(0x02, raw)


def oid(dotted):
    parts = [int(part) for part in dotted.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def bit_string(data):
    return tlv(0x03, b'\x00' + data)


def octet_string(data):
    return tlv(0x04, data)


def utf8(text):
    return tlv(0x0c, text.encode())


def generalized_time(text):
    return tlv(0x18, text.encode())


def explicit(number, content):
    return tlv(0xa0 | number, content)


def boolean(value):
    return tlv(0x01, b'\xff' if value else b'\x00')


def name(common_name):
    return sequence(set_of(sequence(oid('2.5.4.3'), utf8(common_name))))


def ed521_algorithm():
    return sequence(oid(ED521_OID))


def ed521_spki(public):
    return sequence(ed521_algorithm(), bit_string(public))


def pem(label, der):
    text = base64.b64encode(der).decode()
    return f'-----BEGIN {label}-----\n' + '\n'.join(text[i:i + 64] for i in range(0, len(text), 64)) + f'\n-----END {label}-----\n'


def utc_time(text):
    return tlv(0x17, text.encode())


def implicit(number, content, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | number, content)


def extension(identifier, value, critical=False):
    return sequence(oid(identifier), *([boolean(True)] if critical else []), octet_string(value))


def key_usage(*bits):
    """KeyUsage as a DER BIT STRING without trailing zero bits (X.690 11.2.2)."""
    value = 0
    for bit in bits:
        value |= 1 << (15 - bit)
    raw = value.to_bytes(2, 'big').rstrip(b'\x00') or b'\x00'
    unused = 0
    last = raw[-1]
    while last and not last & 1:
        last >>= 1
        unused += 1
    return tlv(0x03, bytes([unused]) + raw)
