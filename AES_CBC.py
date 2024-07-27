import matplotlib.pyplot as plt
import cv2
import numpy as np
from PIL import Image
from IPython.display import display
import io
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import timeit
def image_to_bytes(image_path):
    with Image.open(image_path) as img:
        img = img.convert("RGB")
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='BMP')
        img_bytes = img_bytes.getvalue()
    return img, img_bytes
def encrypt_image_bytes(img_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(img_bytes, AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return encrypted_bytes
def encrypted_bytes_to_image(encrypted_bytes, width, height):
    # Ensure the byte array has the right length
    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)[:width * height * 3]
    encrypted_image = encrypted_array.reshape((height, width, 3))
    return Image.fromarray(encrypted_image)
def decrypt_image_bytes(encrypted_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
    decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
    return decrypted_bytes
def bytes_to_image(decrypted_bytes):
    img_stream = io.BytesIO(decrypted_bytes)
    img = Image.open(img_stream)
    return img
key = os.urandom(16)
iv = os.urandom(16)

encryption_start_time = timeit.default_timer()
image_path = 'Y2.jpg'  # Path to the uploaded image
original_img, img_bytes = image_to_bytes(image_path)
img_width, img_height = original_img.size
print(f"Image size: {img_width}x{img_height}")
img2 = Image.open(image_path)
display(img2)
encrypted_bytes = encrypt_image_bytes(img_bytes, key, iv)
print(f"Encrypted {len(encrypted_bytes)} bytes.")

cipher_img = encrypted_bytes_to_image(encrypted_bytes, img_width, img_height)

display(cipher_img)

encryption_end_time = timeit.default_timer()
encryption_time = encryption_end_time - encryption_start_time
print(f"Encryption Time: {encryption_time:.6f} seconds")
decrypted_start_time = timeit.default_timer()

decrypted_bytes = decrypt_image_bytes(encrypted_bytes, key, iv)
print(f"Decrypted {len(decrypted_bytes)} bytes.")

decrypted_img = bytes_to_image(decrypted_bytes)
display(decrypted_img)

decrypted_end_time = timeit.default_timer()
decrypted_time = decrypted_end_time - decrypted_start_time
print(f"Decryption Time: {decrypted_time:.6f} seconds")
