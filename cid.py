#!/usr/bin/python3
'''
decode a CID (Content IDentifier) as used in IPFS

see https://github.com/multiformats/cid

To decode a CID, follow the following algorithm:

1. * If it's a string (ASCII/UTF-8):
     * If it is 46 characters long and starts with Qm..., it's a CIDv0. Decode
       it as base58btc and continue to step 2.
     * Otherwise, decode it according to the multibase spec and:
       * If the first decoded byte is 0x12, return an error. CIDv0 CIDs
         may not be multibase encoded and there will be no CIDv18
         (0x12 = 18) to prevent ambiguity with decoded CIDv0s.
       * Otherwise, you now have a binary CID. Continue to step 2.
2. Given a (binary) CID (cid):
   * If it's 34 bytes long with the leading bytes [0x12, 0x20, ...],
     it's a CIDv0.
     * The CID's multihash is cid.
     * The CID's multicodec is DagProtobuf
     * The CID's version is 0.
   * Otherwise, let N be the first varint in cid. This is the CID's version.
     * If N == 0x01 (CIDv1):
       * The CID's multicodec is the second varint in cid
       * The CID's multihash is the rest of the cid (after the second varint).
       * The CID's version is 1.
     * If N == 0x02 (CIDv2), or N == 0x03 (CIDv3), the CID version is reserved.
     * If N is equal to some other multicodec, the CID is malformed.

for multicodecs, see //github.com/multiformats/multicodec/blob/master/table.csv

some immediately useful ones:
  0: "identity", raw binary
  0x55 ('U'): "raw", raw binary
  0x70 ('p'): "dag-pb" (DagProtobuf), MerkleDAG protobuf, used by CIDv0

the final hash is a representation of the contents of the Merkle DAG of the
data. from looking at several files under ~/.ipfs/blocks, it seems to be of
the form: 0x0a <size of remainder of block (past this size varint)>
0x08 0x02 0x12 <size of data minus 9(?)> 0x18 <size of data itself>
for example,
.ipfs/blocks/OO/CIQBT4N7PS5IZ5IG2ZOUGKFK27IE33WKGJNDW2TY3LSBNQ34R6OVOOQ
starts with (in hex) 0a 92 08 02 12 81 08 <data follows>, which after
decoding the varints is: 10, 1170, 8, 2, 18, 1153. following the data we find:
18 8a 09, which decodes to 24, 1162.

The file itself, with the header and trailer bytes removed, is from
https://github.com/ipfs/go-ipfs/blob/master/assets/init-doc/security-notes,
and has 1162 bytes. The corresponding CID is
QmQ5vhrL7uv6tuoN9KeVBwd4PwfQkXdVVmDLUZuTNxqgvm. It has 1173 bytes total
(the 1170 above plus the initial 3 bytes 0a 92 08).
'''
import sys, logging, base58  # pylint: disable=multiple-imports
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

def decode_cid(cid):
    '''
    decode a CID according to given specification

    >>> decode_cid(b'QmPK1s3pNYLi9ERiq3BDxKa4XosgWwFRQUydHUtz4YgpqB')
    '0e7071c59df3b9454d1d18a15270aa36d54f89606a576dc621757afd44ad1d2e'
    '''
    logging.debug('CID: %r', cid)
    bcid, encoded, hashed = b'', b'', b''
    if len(cid) == 46 and cid.startswith(b'Qm'):
        logging.debug('we appear to have a valid CIDv0')
        bcid = base58.b58decode(cid)
    else:
        raise NotImplementedError('Multibase not yet implemented')
    logging.debug('binary CID: %r', bcid)
    if len(bcid) == 34 and bcid.startswith(b'\x12\x20'):
        logging.debug('multicodec: DagProtobuf, multihash: %r', bcid)
        encoded = bcid
    else:
        cid_version, encoded = decode_varint(bcid)
        logging.debug('cid_version: %s', cid_version)
        if cid_version == 1:
            multicodec, encoded = decode_varint(encoded)
            logging.debug('multicodec: %s, multihash: %r', multicodec, encoded)
        elif cid_version in [2, 3]:
            raise NotImplementedError('Reserved version %d' % cid_version)
        else:
            raise NotImplementedError('Malformed CID')
    multihash, multihashed = decode_varint(encoded)
    if multihash != 0x12:
        raise NotImplementedError('Only sha256 is currently supported')
    hashed_size, hashed = decode_varint(multihashed)
    if hashed_size != 32:  # 0x20 (space)
        raise NotImplementedError('Only 32 bytes (sha256) is supported')
    return hashed.hex()

def decode_varint(bytestring):
    '''
    decode a variable-length unsigned integer

    return the integer and the remainder of the bytestring

    see https://github.com/multiformats/unsigned-varint

    >>> decode_varint(bytes([0b00000001]))
    (1, b'')
    >>> decode_varint(bytes([0b01111111]))
    (127, b'')
    >>> decode_varint(bytes([0b10000000, 0b00000001]))
    (128, b'')
    >>> decode_varint(bytes([0b11111111, 0b00000001]))
    (255, b'')
    >>> decode_varint(bytes([0b10101100, 0b00000010]))
    (300, b'')
    >>> decode_varint(bytes([0b10000000, 0b10000000, 0b00000001]))
    (16384, b'')
    '''
    result = 0
    varint = []
    index = 0
    for index, byte in enumerate(bytestring):
        varint.append(byte)
        if not byte & 0b10000000:
            break
    for byte in varint[::-1]:
        result <<= 7
        result |= byte & 0b01111111
    return result, bytestring[index + 1:]

if __name__ == '__main__':
    print(decode_cid(*(arg.encode() for arg in sys.argv[1:])))
