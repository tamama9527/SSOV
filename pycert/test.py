from OpenSSL import crypto


st_cert = open('my_cert.crt', 'rt').read()

c = crypto
cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

certIssue = cert.get_issuer()

print("version:",cert.get_version()+1)
print("serial_number:",hex(cert.get_serial_number()))
print("use sign algorithm:",cert.get_signature_algorithm().decode("UTF-8"))
print("issuer:",certIssue)
print('count:',cert.get_extension_count())
for i in range(cert.get_extension_count()):
    print(i)
    print(cert.get_extension(i))
