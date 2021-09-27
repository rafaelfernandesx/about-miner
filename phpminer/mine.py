import hashlib, struct, sys

ver = 2
prev_block = "000000000000015f416afc2a44461adb178764a4fb45e5935c0a5717edf451a8"
mrkl_root = "3b135862ce5db3fa99836afd8b544e6385c5215cd68034227ced81caea0e961e"
time_ = 0x518F0A11  # 2014-02-20 04:57:25
bits = 0x1a01aa3d

# https://en.bitcoin.it/wiki/Difficulty
exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
target_str = bytes.fromhex(target_hexstr)

# nonce = 2315762778 #target nonce
nonce = 2315552778
while nonce < 0x100000000:

    header = (struct.pack("<L", ver) + bytes.fromhex(prev_block)[::-1] + bytes.fromhex(mrkl_root)[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = hashlib.sha256(
        hashlib.sha256(header).digest()
        ).digest()

    # print(nonce, hash[::-1].hex())
    if hash[::-1] < target_str:
        print('success')
        break
    nonce += 1
