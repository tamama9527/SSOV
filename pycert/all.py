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

def create_certificate_from_CSR(rootCA_cert, rootCA_private_key, csr, days = 365):
	# Step 1: Prepare X.509 Certificate
	cert = X509.X509()
	serial = struct.unpack("<Q", os.urandom(8))[0]
	cert.set_serial_number(serial)
	cert.set_version(3)
	# Step 2: Set Expired Date
	t = int(time.time())
	now = ASN1.ASN1_UTCTIME()
	now.set_time(t)
	expire = ASN1.ASN1_UTCTIME()
	expire.set_time(t + days * 24 * 60 * 60)
	cert.set_not_before(now)
	cert.set_not_after(expire)
	# Step 3: Set X.509 Extensions
	cert.add_ext(X509.new_extension('nsComment', 'SSL sever'))
	cert.add_ext(X509.new_extension('keyUsage', 'Digital Signature')) 
	cert.add_ext(X509.new_extension('keyUsage', 'Key Encipherment', 1)) # 1 means critical
	cert.add_ext(X509.new_extension('keyUsage', 'Data Encipherment',1))
	cert.add_ext(X509.new_extension('keyUsage', 'Key Agreement', 1))
	cert.add_ext(X509.new_extension('extendedKeyUsage', 'clientAuth'))
	cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
	ext = X509.new_extension('1.2.3.412', 'ASN1:UTF8String:My custom extension\'s value')
# If required: ext.set_critical(1)
	cert.add_ext(ext)
	# Step 4: Set Subject and Public Key from CSR
	cert.set_issuer(rootCA_cert.get_issuer())
	cert.set_subject(csr.get_subject())
	cert.set_pubkey(csr.get_pubkey())
	# Step 5: Use Private Key of Root CA or CA to sign this X.509 certificate
	cert.sign(rootCA_private_key, 'sha256')

	return cert

def create_Signed_Certificate_Request(csr_info, key_len=2048, sign_method="sha256"):
	# Step 1: Create a RSA key pair (public/private key)
	rsa_keypair = generate_rsa_keypair(key_len, 65537)
	evp_private_key = EVP.PKey()
	evp_private_key.assign_rsa(rsa_keypair)
	# Step 2: Create a X.509 request 
	csr = X509.Request()
	csr.set_pubkey(evp_private_key)
	# Step 3: Set CSR information
	x509_name = csr.get_subject()
	x509_name.C = csr_info['C']
	x509_name.CN = csr_info['CN']
	x509_name.ST = csr_info['ST']
	x509_name.O = csr_info['O']
	x509_name.OU = csr_info['OU']
	# Step 4: Use RSA private key to sign it
	csr.sign(evp_private_key, sign_method)
	return csr, evp_private_key

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
	root_ca_cert.add_ext(X509.new_extension('keyUsage', 'Key keyCertSign', 1))
	
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
	root_ca_cert, root_ca_private_key = create_self_signed_RootCA_certificate(root_ca_info)

	with open('root_ca_cert.crt', 'wb') as f:
		f.write(root_ca_cert.as_pem())
	with open('root_ca_private_key.pem', 'wb') as f:
		f.write(root_ca_private_key.as_pem(cipher=None))
	with open('root_ca_public_key.pem', 'wb') as f:
		f.write(root_ca_cert.get_pubkey().as_pem(cipher=None))
	# Generate CSR for signed Certificate
	name = ['as','ap','vehicle']
	for i in name:
		csr_info = {}
		csr_info['C'] = "TW"
		csr_info['CN'] = "MyCompany-Certificate"
		csr_info['ST'] = "."
		csr_info['O'] = "ijeCorp Ltd"+str(i)+"."
		csr_info['OU'] = "Security"
		csr, ca_private_key = create_Signed_Certificate_Request(csr_info);

		# Use Root CA's private key to sign a certificate from CSR
		cert = create_certificate_from_CSR(root_ca_cert, root_ca_private_key, csr)
		with open(i+'.crt', 'wb') as f:
			f.write(cert.as_pem()) 
		with open(i+'.pem', 'wb') as f:
			f.write(ca_private_key.as_pem(cipher=None))
