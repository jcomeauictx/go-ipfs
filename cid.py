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
'''
import sys, logging, base58  # pylint: disable=multiple-imports
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

def decode_cid(cid):
    '''
    decode a CID according to given specification
    '''
    logging.debug('CID: %r', cid)
    bcid = b''
    if len(cid) == 46 and cid.startswith(b'Qm'):
        logging.debug('we appear to have a valid CIDv0')
        bcid = base58.b58decode(cid)
    else:
        raise NotImplementedError('Multibase not yet implemented')
    logging.debug('binary CID: %r', bcid)
    if len(bcid) == 34 and bcid.startswith(b'\x12\x20'):
        logging.debug('multicodec: DagProtobuf, multihash: %r', bcid)
    else:
        cid_version, bcid = decode_varint(bcid)
        logging.debug('cid_version: %s', cid_version)
        if cid_version == 1:
            multicodec, bcid = decode_varint(bcid)
            logging.debug('multicodec: %s, multihash: %r', multicodec, bcid)
        elif cid_version in [2, 3]:
            raise NotImplementedError('Reserved version %d' % cid_version)
        else:
            raise NotImplementedError('Malformed CID')

def decode_varint(varint):
    '''
    decode a variable-length unsigned integer

    see https://github.com/multiformats/unsigned-varint

    >>> decode_varint(bytes([0b00000001]))
    1
    >>> decode_varint(bytes([0b01111111]))
    127
    >>> decode_varint(bytes([0b10000000, 0b00000001]))
    128
    >>> decode_varint(bytes([0b11111111, 0b00000001]))
    255
    >>> decode_varint(bytes([0b10101100, 0b00000010]))
    300
    >>> decode_varint(bytes([0b10000000, 0b10000000, 0b00000001]))
    16384
    '''
    result = 0
    for byte in varint[::-1]:
        result <<= 7
        result |= byte & 0b01111111
    return result

if __name__ == '__main__':
    decode_cid(*(arg.encode() for arg in sys.argv[1:]))
