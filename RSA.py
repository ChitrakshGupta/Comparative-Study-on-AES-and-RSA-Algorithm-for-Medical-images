import matplotlib.pyplot as plt
import cv2
import numpy as np
from PIL import Image
from IPython.display import display
import io
import os
import timeit
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def image_to_bytes(image_path):
    with Image.open(image_path) as img:
        img = img.convert("RGB")
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='BMP')
        img_bytes = img_bytes.getvalue()
    return img, img_bytes

def encrypt_image_bytes(img_bytes, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_bytes = b''
    chunk_size = 86  # For a 1024-bit RSA key, chunk size is typically 86 bytes
    for i in range(0, len(img_bytes), chunk_size):
        chunk = img_bytes[i:i+chunk_size]
        encrypted_bytes += cipher_rsa.encrypt(chunk)
    return encrypted_bytes

def encrypted_bytes_to_image(encrypted_bytes, width, height):
    # Ensure the byte array has the right length
    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)[:width * height * 3]
    encrypted_image = encrypted_array.reshape((height, width, 3))
    return Image.fromarray(encrypted_image)

def decrypt_image_bytes(encrypted_bytes, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_bytes = b''
    chunk_size = 128  # For a 1024-bit RSA key, chunk size is typically 128 bytes
    for i in range(0, len(encrypted_bytes), chunk_size):
        chunk = encrypted_bytes[i:i+chunk_size]
        decrypted_bytes += cipher_rsa.decrypt(chunk)
    return decrypted_bytes

def bytes_to_image(decrypted_bytes):
    img_stream = io.BytesIO(decrypted_bytes)
    img = Image.open(img_stream)
    return img

# Generate RSA keys
key = RSA.generate(1024)
public_key = key.publickey()
private_key = key

# Extract and print p and q
p = key.p
q = key.q
print(f"Prime numbers used (p, q): ({p}, {q})")

# Measure encryption time
encryption_start_time = timeit.default_timer()
image_path = 'Y3.jpg'  # Path to the uploaded image
original_img, img_bytes = image_to_bytes(image_path)

img_width, img_height = original_img.size
print(f"Image size: {img_width}x{img_height}")

# Display original image
img2 = Image.open(image_path)
display(img2)

# Encrypt image bytes
encrypted_bytes = encrypt_image_bytes(img_bytes, public_key)
print(f"Encrypted {len(encrypted_bytes)} bytes.")

# Convert encrypted bytes to image
cipher_img = encrypted_bytes_to_image(encrypted_bytes, img_width, img_height)
cipher_img.save('cipherRSA.png')
display(cipher_img)

encryption_end_time = timeit.default_timer()
encryption_time = encryption_end_time - encryption_start_time
print(f"Encryption Time: {encryption_time:.6f} seconds")

# Measure decryption time
decrypted_start_time = timeit.default_timer()

# Decrypt image bytes
decrypted_bytes = decrypt_image_bytes(encrypted_bytes, private_key)
print(f"Decrypted {len(decrypted_bytes)} bytes.")

# Convert decrypted bytes to image
decrypted_img = bytes_to_image(decrypted_bytes)
decrypted_img.save('decryptedRSA.png')
display(decrypted_img)

decrypted_end_time = timeit.default_timer()
decrypted_time = decrypted_end_time - decrypted_start_time
print(f"Decryption Time: {decrypted_time:.6f} seconds")
