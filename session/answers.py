'''
#markdown
# Session Objectives
* Learn HD Wallets (BIP32)
* Learn HD Wallet Organization (BIP44)
* Learn Mnemonic Backup (BIP39)
* Create Wallet Seeds
#endmarkdown
#markdown
# HD Wallets
#endmarkdown
#markdown
# Motivation
* Reusing Addresses compromises privacy
* Creating a new private key means having to back it up
* Core wallet used to generate 100 private keys at a time
* Backing up many private keys is not easy to do on paper
#endmarkdown
#markdown
# Deterministic Wallets
* Single seed can generate virtually infinite private keys
* (N+1)st private key generated from the Nth private key and a code
* Used first in Armory back in 2012
#endmarkdown
#markdown
# Naive Deterministic Wallet
* $eG=P$
* $(e+1)G=eG+G=P+G$
* $(e+2)G=eG+2G=P+2G$
* ...
* Store private key $e$ and reveal $P$ to payer
* No privacy from chain analysis or payer
#endmarkdown
#markdown
# Robust Deterministic Wallet
* $eG=P$, $c$ is a shared secret, $H$ is a hash function
* $(e+H(c,P,1))G=P+H(1+P,c)G$
* $(e+H(c,P,2))G=P+H(2+P,c)G$
* ...
* Store private key $e$ and reveal $P$, $c$ to payer
* Privacy from chain analysis
* No privacy from payers
#endmarkdown
#markdown
# Message Authentication Codes
* Used for verifying that a message is authentic when you share a secret already
* HMAC is an implementation of MAC where H stands for "hash-based"
* Most cryptographic hash functions (like sha256) have an HMAC implementation
#endmarkdown
#markdown
# Heirarchical Deterministic Wallets (BIP32)
* Single seed + chain code (shared secret)
* The master private key can generate $2^{32}$ child private keys
* Every child private key can also generate $2^{32}$ child private keys
* Revealing a child public key does not reveal the parent public key
* Adds privacy from recpients
#endmarkdown
#markdown
# Implementation
* $eG=P$, $e$ is the private key, $P$ is the public key
* $c$ is the chaincode $H$ is the HMAC-SHA512 function
* $2^{31}$ hardened keys and $2^{31}$ unhardened keys
* Hardened means the public key ($P$) and chain code ($c$) *cannot* derive the child public key.
* Unhardened means the public key ($P$) and chain code ($c$) *can* derive the child public key
#endmarkdown
#markdown
# Defining a HD Public Key
* public key - normal ECC public key (33 bytes)
* chain code - 32-byte shared secret with payers
* depth - 0 is root, 1 is a child of root, 2 is grandchild of root, etc.
* fingerprint- `00000000` for root, first 4 bytes of parent pubkey's hash160.
* child number - ordering from parent
#endmarkdown
#markdown
# Defining a HD Private Key
* private key - normal ECC private key (33 bytes)
* chain code - 32-byte shared secret with payers
* depth - 0 is root, 1 is a child of root, 2 is grandchild of root, etc.
* fingerprint- `00000000` for root, first 4 bytes of parent pubkey's hash160.
* child number - ordering from parent
#endmarkdown
#markdown
# Process for generating a Master HD Private Key
* Create a seed of 128 to 512 bits
* Calculate $h=H(d,s)$ where $H$ is HMAC-SHA512, $d$ is `Bitcoin seed` and $s$ is the seed.
* Master secret = first 256 bits of $h$ in big-endian
* Master chain code = last 256 bits of $h$ in big-endian
#endmarkdown
#code
>>> # Example Master Key Generation
>>> from ecc import PrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, raw_decode_base58
>>> from hd import HDPrivateKey
>>> seed = b'jimmy@programmingblockchain.com Jimmy Song'
>>> h = hmac_sha512(b'Bitcoin seed', seed)
>>> private_key = PrivateKey(secret=big_endian_to_int(h[:32]))
>>> chain_code = h[32:]
>>> master = HDPrivateKey(
...     private_key=private_key,
...     chain_code=chain_code,
...     testnet=True,
... )
>>> print(master.bech32_address())
tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg

#endcode
#code
>>> import hd, tx

#endcode
#unittest
hd:HDTest:test_from_seed:
#endunittest
#markdown
# HD Child Derivation
#endmarkdown
#markdown
# Deriving the child key
* $eG=P$ where $e$ is the private key and $P$ is the public key
* $H$ is HMAC-SHA512, $c$ is the chain code, $i$ is the child number
* $h$ is the derivation source
* For hardened children, $h=H(c,e||i)$
* For unhardened children, $h=H(c,P||i)$
* $e_{child}=h_l+e$ where $h_l$ is the first 256 bits of $h$
* $P_{child}=h_l*G+P$
* $c_{child}=h_r$ where $h_r$ is the last 256 bits of $h$
#endmarkdown
#code
>>> # Example Unhardened Child Derivation
>>> from ecc import N
>>> from hd import HDPrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, int_to_big_endian
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> index = 0
>>> data = master.private_key.point.sec() + int_to_big_endian(index, 4)
>>> h = hmac_sha512(master.chain_code, data)
>>> secret = (big_endian_to_int(h[:32]) + master.private_key.secret) % N
>>> unhardened_child = HDPrivateKey(
...     private_key=PrivateKey(secret=secret),
...     chain_code=h[32:],
...     depth=master.depth + 1,
...     parent_fingerprint=master.fingerprint(),
...     child_number=index,
...     testnet=master.testnet,
... )
>>> print(unhardened_child.bech32_address())
tb1qu6mnnk54hxfhy4aj58v0w6e7q8hghtv8wcdl7g

#endcode
#code
>>> # Example Hardened Child Derivation
>>> from ecc import N
>>> from hd import HDPrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, int_to_big_endian
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> index = 0x80000002
>>> data = int_to_big_endian(master.private_key.secret, 33) + int_to_big_endian(index, 4)
>>> h = hmac_sha512(master.chain_code, data)
>>> secret = (big_endian_to_int(h[:32]) + master.private_key.secret) % N
>>> hardened_child = HDPrivateKey(
...     private_key=PrivateKey(secret=secret),
...     chain_code=h[32:],
...     depth=master.depth + 1,
...     parent_fingerprint=master.fingerprint(),
...     child_number=index,
...     testnet=master.testnet,
... )
>>> print(hardened_child.bech32_address())
tb1qscu8evdlqsucj7p84xwnrf63h4jsdr5yqga8zq

#endcode
#unittest
hd:HDTest:test_child:
#endunittest
#markdown
# Path Notation
* m/x/y/z
* m/1/2'/0 means the root key's 1st unhardened child's 2nd hardened child's 0th unhardened child
* / delimits each level and ' indicates hardened
#endmarkdown
#code
>>> # example of private key path traversal
>>> from hd import HDPrivateKey
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> current = master
>>> path = "m/0/1'/2/3'"
>>> components = path.split('/')[1:]
>>> for child in components:
...     if child.endswith("'"):
...         index = int(child[:-1]) + 0x80000000
...     else:
...         index = int(child)
...     current = current.child(index)
>>> print(current.bech32_address())
tb1q423gz8cenqt6vfw987vlyxql0rh2jgh4sy0tue

#endcode
#unittest
hd:HDTest:test_traverse:
#endunittest
#markdown
# Serialization
#endmarkdown
#markdown
# HD Key Serialization
* xprv/xpub standard (BIP32) used for p2pkh
* yprv/ypub standard (BIP49) used for p2sh-p2wpkh
* zprv/zpub standard (BIP84) used for p2wpkh
#endmarkdown
#markdown
# xpub
* version - 4 bytes `0488b21e`
* depth - 1 byte
* parent fingerprint - 4 bytes
* child number - 4 bytes, big endian
* chain code - 32 bytes
* compressed SEC - 33 bytes
* Result is base58-encoded
#endmarkdown
#markdown
![](/files/session3/xpub.png)
#endmarkdown
#code
>>> # Example to create an xpub
>>> from hd import HDPrivateKey
>>> from helper import encode_base58_checksum, int_to_byte, int_to_big_endian
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> hd_priv = HDPrivateKey.from_seed(passphrase)
>>> raw = bytes.fromhex('0488b21e')
>>> raw += int_to_byte(hd_priv.depth)
>>> raw += hd_priv.parent_fingerprint
>>> raw += int_to_big_endian(hd_priv.child_number, 4)
>>> raw += hd_priv.chain_code
>>> raw += hd_priv.pub.point.sec()
>>> print(encode_base58_checksum(raw))
xpub661MyMwAqRbcEpBhPYKfaLbRYynwb4fyL7N7xxB98h3sH5br3Tu4iNSe2S7yyP3AFXFoYRyZUWXJFw8o4sAaSTTQZLf8y3YJLRnJqSfnoWT

#endcode
#markdown
# xprv
* version - 4 bytes `0488ade4`
* depth - 1 byte
* parent fingerprint - 4 bytes
* child number - 4 bytes, big endian
* chain code - 32 bytes
* private key prepended with `00` - 33 bytes
* Result is base58-encoded
#endmarkdown
#exercise
#### Create an xprv from your seed

Spec is above, the only things that need to change versus the xpub is the version and the private key instead of the compressed SEC
---
>>> from hd import HDPrivateKey
>>> from helper import encode_base58_checksum, int_to_byte, int_to_big_endian
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # add the version which should be '0488ade4' in binary
>>> raw = bytes.fromhex('0488ade4')  #/
>>> # add the depth as a single byte
>>> raw += int_to_byte(hd_priv.depth)  #/
>>> # add the parent fingerprint
>>> raw += hd_priv.parent_fingerprint  #/
>>> # add the child number in big endian 4 bytes
>>> raw += int_to_big_endian(hd_priv.child_number, 4)  #/
>>> # add the chain code
>>> raw += hd_priv.chain_code  #/
>>> # add the private key in big endian 33 bytes
>>> raw += int_to_big_endian(hd_priv.private_key.secret, 33)  #/
>>> # print the base58
>>> print(encode_base58_checksum(raw))  #/
xprv9s21ZrQH143K2L7EHWnfDCegzwxTBbx7xtSXAZmXaMWtQHGhVvapAa8ABAv7PmkCkcrxhVdSF5YHCA5n6u8CdjsgMRACrSbX1VQrMPQuVmJ

#endexercise
#unittest
hd:HDTest:test_prv_pub:
#endunittest
#unittest
hd:HDTest:test_parse:
#endunittest
#exercise

#### Create an extended public key

Create a xpub on testnet (should start with tpub)

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # print the xpub
>>> print(hd_priv.xpub())  #/
tpubD6NzVbkrYhZ4WcNYqjJknFvnt6tbaTB2sjxRKWEHUbom2NGZ7gk9rp7UGUCmVszQ3RniA1VS1cMLx7dQTj1pKtuhcwQSeaCXvPNibUHNR3F

#endexercise
#markdown
# BIP44
#endmarkdown
#markdown
# Motivation and Structure
* Give structure to the BIP32 heirarchy
* Purpose - 44' is p2pkh, 49' is p2sh-p2wpkh, 84' is p2wpkh
* Coin - 0' is BTC, 1' is testnet BTC, many others [here](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
* Account - Hardened child that corresponds to a payer
* Chain - Unhardened child corresponding to receive addresses and change addresses (external/internal)
* Address - Unhardened child to get an actual child
#endmarkdown
#markdown
# Examples
* m/44'/0'/0'/0/0 - p2pkh, Mainnet Bitcoin first account, external first address
* m/44'/1'/2'/1/3 - p2pkh, Testnet Bitcoin, second account, internal, 4th address
* m/49'/0'/1'/1/0 - p2sh-p2wpkh, Mainnet Bitcoin, second account, internal, first address
* m/84'/1'/0'/0/2 - p2wpkh, Testnet Bitcoin, first count, external, third address
#endmarkdown
#code
>>> # Example of getting p2pkh/p2sh-p2wpkh/p2wpkh testnet addresses
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)
>>> # p2pkh
>>> p2pkh_path = "m/44'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2pkh_path).address())
mpLAmKy2kMhTFSHRKcJzhdRTMjWYRp5rdt
>>> # p2sh-p2wpkh
>>> p2sh_p2wpkh_path = "m/49'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2sh_p2wpkh_path).p2sh_p2wpkh_address())
2NBZYna15Fp45bFmice7Ld99B6HvwHRTNNz
>>> # p2wpkh
>>> p2wpkh_path = "m/84'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2wpkh_path).bech32_address())
tb1qrpeej834jx0ll3euv86fg09865falq83zp7v27

#endcode
#unittest
hd:HDTest:test_get_address:
#endunittest
#exercise

#### Create external p2pkh, p2sh_p2wpkh and p2wpkh addresses

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # print the p2pkh address
>>> print(hd_priv.get_p2pkh_receiving_address())  #/
mpLAmKy2kMhTFSHRKcJzhdRTMjWYRp5rdt
>>> # print the p2sh-pwpkh address
>>> print(hd_priv.get_p2sh_p2wpkh_receiving_address())  #/
2NBZYna15Fp45bFmice7Ld99B6HvwHRTNNz
>>> # print the p2wpkh address
>>> print(hd_priv.get_p2wpkh_receiving_address())  #/
tb1qrpeej834jx0ll3euv86fg09865falq83zp7v27

#endexercise
#exercise

#### Create xpub for account 0

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # calculate the path for purpose=44', coin=1' (testnet), account=0
>>> path = "m/44'/1'/0'"  #/
>>> # print the xpub at that path
>>> print(hd_priv.traverse(path).xpub())  #/
tpubDDNz9YHarfY2LUuBCMs9nw25BfE8LTjXe2YSuqqZCCk4JdvFswmPUa9myShQng1FxHs2Z1bV9Wik5oR69DjJkEsZn2co7ejVKup8iAMNWyc

#endexercise
#markdown
# Mnemonics
#endmarkdown
#markdown
# What is a Mnemonic Backup?
* A way to back up HD wallets
* Easier to remember than base58
* Uses 2048 English words whose first 4 letters differ
* Each word stores 11 bits of information
* There's 1 checksum bit for every 32 bits
#endmarkdown
#markdown
# BIP39
* Specifies Mnemonic Backup standard
* Optional passphrase for more security
* Different numbers of words correspond to different amounts of entropy
* 12, 15, 18, 21 and 24 words allowed
* Hard to brute force, even at 12 words
#endmarkdown
#markdown
# How to generate a Mnemonic
* Start with a 128/160/192/224/256 bit random number
* Divide the number of bits by 32, that's how many checksum bits $n$
* Checksum is the first n bits of the SHA256 of the random number as a big-endian integer
* Combine the bits and checksum to produce a bit array
* There should be some multiple of 11 bits.
* Each 11 bits corresponds to a word as $2^{11}=2048$
#endmarkdown
#code

>>> def secure_mnemonic(entropy=0, num_bits=128):
...     # if we have more than 128 bits, just mask everything but the last 128 bits
...     if len(bin(entropy)) > num_bits+2:
...         entropy &= (1 << num_bits) - 1
...     # xor some random bits with the entropy that was passed in
...     preseed = randbits(num_bits) ^ entropy
...     # convert the number to big-endian
...     s = int_to_big_endian(preseed, 16)
...     # 1 extra bit for checksum is needed per 32 bits
...     checksum_bits_needed = num_bits // 32
...     # the checksum is the sha256's first n bits. At most this is 8
...     checksum = sha256(s)[0] >> (8 - checksum_bits_needed)
...     # we concatenate the checksum to the preseed
...     total = (preseed << checksum_bits_needed) | checksum
...     # now we get the mnemonic passphrase
...     mnemonic = []
...     # now group into groups of 11 bits
...     for _ in range((num_bits + bits_needed) // 11):
...         # grab the last 11 bits
...         current = total & ((1 << 11) - 1)
...         # insert the correct word at the front
...         mnemonic.insert(0, WORD_LIST[current])
...         # shift by 11 bits so we can move to the next set
...         total >>= 11
...     # return the mnemonic phrase by putting spaces between
...     return ' '.join(mnemonic)

#endcode
# Converting a Mnemonic to a Root HD Private key
* Convert mnemonic to a number and verify checksum
* Use the mnemonic in PBKDF2 to generate the seed
* PBKDF2 = Password-based Key Derivation Function 2. Requires some pseudo-random function.
* Pseudo-random function is HMAC-SHA512
* PBKDF2 recursively applies the pseudo-random function $N$ times. $N = 2048$ for BIP39
* PBKDF2 makes brute force attacks much more expensive
#endmarkdown
#code
>>> # Example of mnemonic to HDPrivateKey
>>> from hd import HDPrivateKey
>>> from helper import hmac_sha512_kdf, sha256
>>> from mnemonic import WORD_LOOKUP, WORD_LIST
>>> mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
>>> password = b'TREZOR'
>>> words = mnemonic.split()
>>> if len(words) not in (12, 15, 18, 21, 24):
...     raise ValueError('you need 12, 15, 18, 21, or 24 words')
>>> number = 0
>>> for word in words:
...     index = WORD_LOOKUP[word]
...     number = (number << 11) | index
>>> checksum_bits_length = len(words) // 3
>>> checksum = number & ((1 << checksum_bits_length) - 1)
>>> data_num = number >> checksum_bits_length
>>> data = int_to_big_endian(data_num, checksum_bits_length * 4)
>>> computed_checksum = sha256(data)[0] >> (8 - checksum_bits_length)
>>> if checksum != computed_checksum:
...     raise ValueError('words fail checksum: {}'.format(words))
>>> normalized_words = []
>>> for word in words:
...     normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
>>> normalized_mnemonic = ' '.join(normalized_words)
>>> salt = b'mnemonic' + password
>>> seed = hmac_sha512_kdf(normalized_mnemonic, salt)
>>> print(HDPrivateKey.from_seed(seed).xprv())
xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq

#endcode
#unittest
hd:HDTest:test_from_mnemonic:
#endunittest
#exercise

#### Generate a testnet extended public key at m/84'/1'/0' using the generic mnemonic and your own passphrase

----
>>> from hd import HDPrivateKey
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> path = "m/84'/1'/0'"
>>> # create a private key using the mnemonic, passphrase, path and testnet=True
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, path, True)  #/
>>> # print the xpub
>>> print(hd_priv.xpub())  #/
tpubDD1e7uBTB1CxR8tJYsWswsrJob2R639TRSDgN3eyPyJJ6qoqZwHZ3GWdJ69Ppmpwy6aRhhQmx6WJt4mX7nwpVTU3HAAEY9gaJ32NnF9CjHQ

#endexercise
'''


from io import BytesIO
from unittest import TestCase

from ecc import G, N, PrivateKey, S256Point
from hd import (
    HDPrivateKey,
    HDPublicKey,
    MAINNET_XPRV,
    MAINNET_XPUB,
    MAINNET_YPRV,
    MAINNET_YPUB,
    MAINNET_ZPRV,
    MAINNET_ZPUB,
    TESTNET_XPRV,
    TESTNET_XPUB,
    TESTNET_YPRV,
    TESTNET_YPUB,
    TESTNET_ZPRV,
    TESTNET_ZPUB,
)
from helper import (
    big_endian_to_int,
    byte_to_int,
    encode_base58_checksum,
    hmac_sha512,
    hmac_sha512_kdf,
    int_to_big_endian,
    int_to_byte,
    raw_decode_base58,
    sha256,
)
from mnemonic import WORD_LOOKUP, WORD_LIST


def _get_address(self, purpose, account=0, external=True, address=0):
    if purpose not in ("44'", "49'", "84'"):
        raise ValueError('Cannot create an address without a proper purpose: {}'.format(purpose))
    if self.testnet:
        coin = "1'"
    else:
        coin = "0'"
    if external:
        chain = '0'
    else:
        chain = '1'
    path = "m/{}/{}/{}'/{}/{}".format(purpose, coin, account, chain, address)
    hd_priv = self.traverse(path)
    if purpose == "44'":
        return hd_priv.address()
    elif purpose == "49'":
        return hd_priv.p2sh_p2wpkh_address()
    elif purpose == "84'":
        return hd_priv.bech32_address()


def _prv(self, version):
    raw = version
    raw += int_to_byte(self.depth)
    raw += self.parent_fingerprint
    raw += int_to_big_endian(self.child_number, 4)
    raw += self.chain_code
    raw += int_to_big_endian(self.private_key.secret, 33)
    return encode_base58_checksum(raw)


def xprv_child(self, index):
    if index >= 0x80000000:
        data = int_to_big_endian(self.private_key.secret, 33) + int_to_big_endian(index, 4)
    else:
        data = self.private_key.point.sec() + int_to_big_endian(index, 4)
    h = hmac_sha512(self.chain_code, data)
    secret = (big_endian_to_int(h[:32]) + self.private_key.secret) % N
    private_key = PrivateKey(secret=secret)
    chain_code = h[32:]
    depth = self.depth + 1
    parent_fingerprint = self.pub.hash160()[:4]
    child_number = index
    return HDPrivateKey(
        private_key=private_key,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=self.testnet,
    )


@classmethod
def from_seed(cls, seed, testnet=False):
    h = hmac_sha512(b'Bitcoin seed', seed)
    private_key = PrivateKey(secret=big_endian_to_int(h[:32]))
    chain_code = h[32:]
    return cls(
        private_key=private_key,
        chain_code=chain_code,
        testnet=testnet,
    )


@classmethod
def from_mnemonic(cls, mnemonic, password=b'', path='m', testnet=False):
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError('you need 12, 15, 18, 21, or 24 words')
    number = 0
    for word in words:
        index = WORD_LOOKUP[word]
        number = (number << 11) | index
    checksum_bits_length = len(words) // 3
    checksum = number & ((1 << checksum_bits_length) - 1)
    data_num = number >> checksum_bits_length
    data = int_to_big_endian(data_num, checksum_bits_length * 4)
    computed_checksum = sha256(data)[0] >> (8 - checksum_bits_length)
    if checksum != computed_checksum:
        raise ValueError('words fail checksum: {}'.format(words))
    normalized_words = []
    for word in words:
        normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
    normalized_mnemonic = ' '.join(normalized_words)
    salt = b'mnemonic' + password
    seed = hmac_sha512_kdf(normalized_mnemonic, salt)
    return cls.from_seed(seed, testnet=testnet).traverse(path)


def xpub_child(self, index):
    if index >= 0x80000000:
        raise ValueError('child number should always be less than 2^31')
    data = self.point.sec() + int_to_big_endian(index, 4)
    h = hmac_sha512(key=self.chain_code, msg=data)
    point = self.point + big_endian_to_int(h[:32]) * G
    chain_code = h[32:]
    depth = self.depth + 1
    parent_fingerprint = self.fingerprint()
    child_number = index
    return HDPublicKey(
        point=point,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=self.testnet,
    )


@classmethod
def xprv_parse(cls, s):
    raw = raw_decode_base58(s)
    if len(raw) != 78:
        raise ValueError('Not a proper extended key')
    stream = BytesIO(raw)
    return cls.raw_parse(stream)

@classmethod
def xprv_raw_parse(cls, s):
    version = s.read(4)
    if version in (TESTNET_XPRV, TESTNET_YPRV, TESTNET_ZPRV):
        testnet = True
    elif version in (MAINNET_XPRV, MAINNET_YPRV, MAINNET_ZPRV):
        testnet = False
    else:
        raise ValueError('not an xprv, yprv or zprv: {}'.format(version))
    depth = byte_to_int(s.read(1))
    parent_fingerprint = s.read(4)
    child_number = big_endian_to_int(s.read(4))
    chain_code = s.read(32)
    if byte_to_int(s.read(1)) != 0:
        raise ValueError('private key should be preceded by a zero byte')
    private_key = PrivateKey(secret=big_endian_to_int(s.read(32)))
    return cls(
        private_key=private_key,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=testnet,
    )


def xprv_traverse(self, path):
    current = self
    components = path.split('/')[1:]
    for child in components:
        if child.endswith("'"):
            index = int(child[:-1]) + 0x80000000
        else:
            index = int(child)
        current = current.child(index)
    return current


def _serialize(self, version):
    raw = version
    raw += int_to_byte(self.depth)
    raw += self.parent_fingerprint
    raw += int_to_big_endian(self.child_number, 4)
    raw += self.chain_code
    raw += self.point.sec()
    return raw


def _pub(self, version):
    '''Returns the base58-encoded x/y/z pub.
    Expects a 4-byte version.'''
    raw = self._serialize(version)
    return encode_base58_checksum(raw)


@classmethod
def xpub_parse(cls, s):
    raw = raw_decode_base58(s)
    if len(raw) != 78:
        raise ValueError('Not a proper extended key')
    stream = BytesIO(raw)
    return cls.raw_parse(stream)


@classmethod
def xpub_raw_parse(cls, s):
    version = s.read(4)
    if version in (TESTNET_XPUB, TESTNET_YPUB, TESTNET_ZPUB):
        testnet = True
    elif version in (MAINNET_XPUB, MAINNET_YPUB, MAINNET_ZPUB):
        testnet = False
    else:
        raise ValueError('not an xpub, ypub or zpub: {} {}'.format(s, version))
    depth = byte_to_int(s.read(1))
    parent_fingerprint = s.read(4)
    child_number = big_endian_to_int(s.read(4))
    chain_code = s.read(32)
    point = S256Point.parse(s.read(33))
    return cls(
        point=point,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=testnet,
    )


def xpub_traverse(self, path):
    current = self
    components = path.split('/')[1:]
    for child in components:
        if child[-1:] == "'":
            raise ValueError('HDPublicKey cannot get hardened child')
        current = current.child(int(child))
    return current


class SessionTest(TestCase):

    def test_apply(self):
        HDPrivateKey._get_address = _get_address
        HDPrivateKey._prv = _prv
        HDPrivateKey.child = xprv_child
        HDPrivateKey.from_seed = from_seed
        HDPrivateKey.from_mnemonic = from_mnemonic
        HDPrivateKey.parse = xprv_parse
        HDPrivateKey.raw_parse = xprv_raw_parse
        HDPrivateKey.traverse = xprv_traverse
        HDPublicKey._pub = _pub
        HDPublicKey._serialize = _serialize
        HDPublicKey.child = xpub_child
        HDPublicKey.parse = xpub_parse
        HDPublicKey.raw_parse = xpub_raw_parse
        HDPublicKey.traverse = xpub_traverse
