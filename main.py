from utils import *

if __name__ == "__main__":

    # key exchange demo

    bits = 256
    p_common = generate_prime_number(bits)
    g_common = find_primitive_root(p_common)
    
    print(f"[DH] Common Prime (p) : {p_common}")
    print(f"[DH] Common Generator (g): {g_common}")

    alice_dh = DiffieHellman(p=p_common, g=g_common)
    bob_dh = DiffieHellman(p=p_common, g=g_common)


    alice_pub = alice_dh.generate_keys()
    bob_pub = bob_dh.generate_keys()

    alice_secret = alice_dh.compute_shared_secret(bob_pub)
    bob_secret = bob_dh.compute_shared_secret(alice_pub)

    print(f"[DH] Alice Shared Secret : {alice_secret}")
    print(f"[DH] Bob Shared Secret   : {bob_secret}")
    assert alice_secret == bob_secret, "DHKE Gagal! Secret tidak cocok."
    print(" status: DHKE SUKSES! Shared Key Cocok.\n")


    # elgamal demo
    
    elgamal = ElGamal(bits=256)
    pub_key, priv_key = elgamal.generate_keypair()
    p_elg = pub_key[0]

    pesan = "Halo! Ini pesan rahasia e-voting."
    print(f"[ElGamal] Pesan Asli      : {pesan}")

    # Enkripsi
    ciphertext_list = ElGamal.encrypt_text(pesan, pub_key)
    print(f"[ElGamal] Ciphertext (first char) : {ciphertext_list[0]}")

    # Deskripsi
    pesan_dekripsi = ElGamal.decrypt_text(ciphertext_list, priv_key, p_elg)
    print(f"[ElGamal] Hasil Dekripsi  : {pesan_dekripsi}")
    assert pesan == pesan_dekripsi, "ElGamal Gagal! Teks tidak sama."
    print(" status: ElGamal Encryption/Decryption SUKSES!\n")


    # evote concept
    # E(v1) * E(v2) = E(v1 * v2)
    vote1 = 5
    vote2 = 10

    cipher_v1 = ElGamal.encrypt_number(vote1, pub_key)
    cipher_v2 = ElGamal.encrypt_number(vote2, pub_key)

    # Rekapitulasi suara terenkripsi tanpa membuka isi (Homomorphic Multiplication)
    cipher_total = ElGamal.multiply_homomorphic(cipher_v1, cipher_v2, p_elg)

    # Buka hasil akhir
    total_dekripsi = ElGamal.decrypt_number(cipher_total, priv_key, p_elg)
    
    print(f"[Homomorphic] Vote 1    : {vote1}")
    print(f"[Homomorphic] Vote 2    : {vote2}")
    print(f"[Homomorphic] Hasil Dekripsi (E(v1) * E(v2)) : {total_dekripsi}")
    print(f"[Homomorphic] Hasil Manual  (v1 * v2 mod p)  : {(vote1 * vote2) % p_elg}")
    assert total_dekripsi == (vote1 * vote2) % p_elg
    print(" status: Sifat Homomorfik Berhasil Terbukti!")