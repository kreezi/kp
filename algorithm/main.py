import cryptoContext, mars

mars = mars.MARS(b"1234567891234567")

context = cryptoContext.CryptoContext(mars, "ECB", cryptoContext.PaddingScheme.ZERO)
plaintext = b"HelloWorld!"

encrypt_text = context.encrypt(plaintext)
print(f"Encrypt text: {encrypt_text}")

decrypt_text = context.decrypt(encrypt_text)
print(f"Decrypt text: {decrypt_text}")