import M2Crypto
import time
import os
import struct
from M2Crypto import X509, EVP, ASN1

def generate_rsa_keypair(key_len, exponent):
    def empty_callback():
        pass
    rsa = M2Crypto.RSA.gen_key(key_len, exponent, empty_callback)
    return rsa

def create_self_signed_RootCA_certificate(root_ca_info, sign_method="sha256", days=3650):
    # Setp 1: Create RSA-key pair (public/private key)
    rsa = generate_rsa_keypair(2048, 65537)
    private_key = EVP.PKey()
    private_key.assign_rsa(rsa)
    
    # Step 2-1: Prepare X.509 Certificate Signed Request
    req = X509.Request()
    req.set_pubkey(private_key)
    x509_name = req.get_subject()
    x509_name.C = root_ca_info["C"]
    x509_name.CN = root_ca_info["CN"]
    x509_name.ST = root_ca_info["ST"]
    x509_name.L = root_ca_info["L"]
    x509_name.O = root_ca_info["O"]
    x509_name.OU = root_ca_info["OU"]
    req.sign(private_key,sign_method)
    # Step 2-2: Prepare X.509 certificate
    root_ca_cert = X509.X509()
    
    serial = struct.unpack("<Q", os.urandom(8))[0]
    root_ca_cert.set_serial_number(serial)
    root_ca_cert.set_version(3)
    # Setp 2-3: Set required information of RootCA certificate
    root_ca_cert.set_issuer(x509_name)
    root_ca_cert.set_subject(root_ca_cert.get_issuer())
    root_ca_cert.set_pubkey(req.get_pubkey())  # Get the CSR's public key    

    # Step 2-4: Set Valid Date for RootCA certificate
    t = int(time.time())
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(t + days * 24 * 60 * 60)
    root_ca_cert.set_not_before(now)
    root_ca_cert.set_not_after(expire)
    # Step 3: Add Extensions for this Root CA certificate
    root_ca_cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
    root_ca_cert.add_ext(X509.new_extension('subjectKeyIdentifier', root_ca_cert.get_fingerprint()))
    
    # Step 4: Use Root CA's RSA private key to sign this certificate
    root_ca_cert.sign(private_key, sign_method)
    return root_ca_cert, private_key

if __name__ == '__main__':
    # Generate a Self-Signed Root CA Certificate
    root_ca_info = {}
    root_ca_info['C'] = "TW"
    root_ca_info['CN'] = "Root CA Certificate"
    root_ca_info['ST'] = "Taiwan"
    root_ca_info['O'] = "ijeCorp Ltd."
    root_ca_info['OU'] = "Security"
    root_ca_info['L'] = "Taipei"
    
    root_ca_cert, private_key = create_self_signed_RootCA_certificate(root_ca_info)
    with open('root_ca_cert.crt', 'wb') as f:
        f.write(root_ca_cert.as_pem())
    with open('root_ca_private_key.pem', 'wb') as f:
        f.write(private_key.as_pem(cipher=None))
    with open('root_ca_public_key.pem', 'wb') as f:
        f.write(root_ca_cert.get_pubkey().as_pem(cipher=None))
