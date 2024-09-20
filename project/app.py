from flask import Flask, render_template, request, redirect, url_for
import numpy as np

app = Flask(__name__)

# Fungsi Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    encrypted = ""
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]

    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 256
        encrypted += chr(value)
    return encrypted

def vigenere_decrypt(ciphertext, key):
    decrypted = ""
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]

    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 256
        decrypted += chr(value)
    return decrypted

# Fungsi Playfair Cipher
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Huruf J dihapus dari alfabet
    key = key.upper().replace("J", "I")  # Ganti J dengan I sesuai aturan Playfair
    key = ''.join(sorted(set(key), key=key.index))  # Hilangkan duplikat
    key += ''.join(filter(lambda x: x not in key, alphabet))
    return [key[i:i + 5] for i in range(0, 25, 5)]  # Bagi menjadi 5x5 grid

def playfair_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    encrypted = ""
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")  # Ganti J dengan I dan hilangkan spasi

    # Filter hanya huruf A-Z
    plaintext = ''.join(filter(str.isalpha, plaintext))

    # Sisipkan 'X' jika ada huruf berulang dalam sepasang atau panjangnya ganjil
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            plaintext = plaintext[:i + 1] + 'X' + plaintext[i + 1:]
        i += 2

    if len(plaintext) % 2 != 0:  # Jika panjangnya ganjil, tambahkan 'X'
        plaintext += 'X'

    for i in range(0, len(plaintext), 2):
        a = plaintext[i]
        b = plaintext[i + 1]
        row_a, col_a = divmod("".join(matrix).index(a), 5)
        row_b, col_b = divmod("".join(matrix).index(b), 5)

        if row_a == row_b:  # Huruf-huruf berada di baris yang sama
            encrypted += matrix[row_a][(col_a + 1) % 5]
            encrypted += matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:  # Huruf-huruf berada di kolom yang sama
            encrypted += matrix[(row_a + 1) % 5][col_a]
            encrypted += matrix[(row_b + 1) % 5][col_b]
        else:  # Huruf-huruf berada di baris dan kolom yang berbeda
            encrypted += matrix[row_a][col_b]
            encrypted += matrix[row_b][col_a]

    return encrypted

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    decrypted = ""

    for i in range(0, len(ciphertext), 2):
        a = ciphertext[i]
        b = ciphertext[i + 1]
        row_a, col_a = divmod("".join(matrix).index(a), 5)
        row_b, col_b = divmod("".join(matrix).index(b), 5)

        if row_a == row_b:  # Huruf-huruf berada di baris yang sama
            decrypted += matrix[row_a][(col_a - 1) % 5]
            decrypted += matrix[row_b][(col_b - 1) % 5]
        elif col_a == col_b:  # Huruf-huruf berada di kolom yang sama
            decrypted += matrix[(row_a - 1) % 5][col_a]
            decrypted += matrix[(row_b - 1) % 5][col_b]
        else:  # Huruf-huruf berada di baris dan kolom yang berbeda
            decrypted += matrix[row_a][col_b]
            decrypted += matrix[row_b][col_a]

    return decrypted

# Fungsi Hill Cipher
# Fungsi untuk mencari GCD (Greatest Common Divisor)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Fungsi untuk mencari invers modular
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# Fungsi untuk menghitung determinan matriks 2x2 mod 26
def matrix_determinant(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26

# Fungsi untuk menghitung adjoin matriks 2x2
def adjugate_matrix(matrix):
    return np.array([[matrix[1][1], -matrix[0][1]], [-matrix[1][0], matrix[0][0]]]) % 26

# Fungsi untuk menghitung invers matriks 2x2 mod 26
def mod_matrix_inverse(matrix, mod):
    det = matrix_determinant(matrix)
    
    # Pastikan determinan memiliki invers mod 26
    if gcd(det, mod) != 1:
        raise ValueError("Matrix is not invertible modulo 26")
    
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        raise ValueError("Determinant has no inverse modulo 26")

    adjugate = adjugate_matrix(matrix)
    inverse_matrix = (det_inv * adjugate) % mod
    return inverse_matrix

# Fungsi Hill Cipher untuk enkripsi
def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper().replace(" ", "")
    while len(plaintext) % 2 != 0:  # Pastikan panjang genap
        plaintext += 'X'

    plaintext_vector = [ord(c) - 65 for c in plaintext]
    ciphertext_vector = []

    for i in range(0, len(plaintext_vector), 2):
        v = np.array([[plaintext_vector[i]], [plaintext_vector[i + 1]]])
        c = np.dot(key_matrix, v) % 26
        ciphertext_vector.extend(c.flatten().astype(int))

    ciphertext = ''.join(chr(num + 65) for num in ciphertext_vector)
    return ciphertext

# Fungsi Hill Cipher untuk dekripsi
def hill_decrypt(ciphertext, key_matrix):
    plaintext_vector = [ord(c) - 65 for c in ciphertext]
    decrypted_vector = []

    # Menghitung invers matriks kunci
    key_matrix_inv = mod_matrix_inverse(key_matrix, 26)

    for i in range(0, len(plaintext_vector), 2):
        v = np.array([[plaintext_vector[i]], [plaintext_vector[i + 1]]])
        p = np.dot(key_matrix_inv, v) % 26
        decrypted_vector.extend(p.flatten().astype(int))

    plaintext = ''.join(chr(num + 65) for num in decrypted_vector)
    return plaintext


@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    input_text = ""
    key = ""
    selected_method = ""
    
    if request.method == 'POST':
        method = request.form['method']
        key = request.form['key']
        action = request.form['action']
        selected_method = method

        # Input teks langsung atau dari file
        if 'text' in request.form and request.form['text'].strip():
            input_text = request.form['text'].strip()
        elif 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            input_text = file.read().decode('utf-8')
        else:
            return "Error: Input tidak valid."

        if method == "vigenere":
            if action == "encrypt":
                result = vigenere_encrypt(input_text, key)
            else:
                result = vigenere_decrypt(input_text, key)
        elif method == "playfair":
            if action == "encrypt":
                result = playfair_encrypt(input_text, key)
            else:
                result = playfair_decrypt(input_text, key)
        elif method == "hill":
            # Menggunakan matriks kunci yang invertible modulo 26
            hill_key_matrix = np.array([[3, 3], [2, 5]])  # Mengganti matriks Hill Cipher
            try:
                if action == "encrypt":
                    result = hill_encrypt(input_text, hill_key_matrix)
                else:
                    result = hill_decrypt(input_text, hill_key_matrix)
            except ValueError as e:
                result = str(e)

    return render_template('index.html', result=result, input_text=input_text, key=key, selected_method=selected_method)

if __name__ == '__main__':
    app.run(debug=True)
