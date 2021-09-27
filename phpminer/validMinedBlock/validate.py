import hashlib

# Read the block
block_hex = open("rawblock.txt", "r").read()

# Convert the hexadecimal representation to raw bytes
block_bin = bytes.fromhex(block_hex)

# Keep only the block header (first 80 bytes)
block_header = block_bin[:80]

# Hash the block header using the SHA256 function twice, then reverse the byte's order
block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()[::-1]

# Convert to hexadecimal and display
print(block_hash.hex())
