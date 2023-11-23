#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "pem.h"
#include "base64.h"

#include <iostream>
#include <string>
#include <cassert>

using namespace CryptoPP;

// BASE64编码
std::string BytesToBase64(byte* s, unsigned int s_len)
{
	std::string encoded;

	StringSource ss(s, s_len, true, new Base64Encoder(new StringSink(encoded), false));
	return encoded;
}
// BASE64解码
std::string Base64ToBytes(byte* s, unsigned int s_len)
{
	std::string decoded;

	StringSource ss(s, s_len, true, new Base64Decoder(new StringSink(decoded)));
	return decoded;
}

void LoadPem(BufferedTransformation& bt, RSA::PublicKey& key) {
	if (CryptoPP::PEM_GetType(bt) > 0) {

		std::cout << "filetype " << PEM_GetType(bt) << std::endl;
		PEM_Load(bt, key);
	}
	else {
		std::cout << "filetype PEM_UNSUPPORTED" << std::endl;
		exit(-1);
	}
}

//把字符串plain中的内容用pubFilename文件中的公钥加密数据并保存到encryptedFilename中。
void Encrypt(const std::string& plain, const char* pubFilename, const char* encryptedFilename)
{
	FileSource files(pubFilename, true, new Base64Decoder);
    RSAES_OAEP_SHA_Encryptor pubkey(files);

    SecByteBlock sbbCipherText(pubkey.CiphertextLength(plain.size()));
    //sbbCipherText.begin();
    AutoSeededRandomPool rng;
    pubkey.Encrypt(
        rng,
        (byte const*)plain.data(),
        plain.size(),
        sbbCipherText.begin());

    FileSink(encryptedFilename).Put(sbbCipherText.begin(), sbbCipherText.size());
}


//根据长度生成公钥和私钥，并分别保存到pubFilename文件和privFilename文件
void GenerateRSAKey(unsigned int keyLength, const char* privFilename, const char* pubFilename)
{
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.GenerateRandomWithKeySize(rng, keyLength);

	Base64Encoder privkeysink(new FileSink(privFilename));  //"privkey.txt"
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	RSAFunction pubkey(privkey);
	Base64Encoder pubkeysink(new FileSink(pubFilename));  //"pubkey.txt"
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
}

//信息加密（公钥写到代码中）
void Encrypt2(const std::string& plain, const char* encryptedFilename = NULL)
{
	std::cout << plain << std::endl;
	//RSAES_OAEP_SHA_Encryptor pubkey(FileSource(pubFilename, true, new Base64Decoder));
	std::string pub1 = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJSZML90i6GFQjxq2PlwDdcODGRWbj3W\
		gh9n4BqTaFutRTpF3DxJdjKKwsKZxWiY02lOYiMKSWHg65tsqV5H+SCTkdSpfbTPSu0OZxhyXVMd\
		OVKCmfm0I32DjaPh/C/KTs8VInxiIJiIDy3TZH4IqP5X+5xP9uZCA2ICbQDBD6jA5cGLcOXli+Qi\
		QSrhhUMABR9xDIyHgQzNI/XCzLvd2xq/DXY39COZtEmqm2sXghzcs1Vi0+0KGm7Z51YZRfTZ4uiL\
		dnKwp2yDuaDpv88rmR/3V0pjSS31anS49bNC0OS/pj1RT+58amwADuty2ZUixWOoYzYFG/HC1Qy5\
		IQ12BQIDAQAB-----END PUBLIC KEY-----";
	std::string pub = "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC1f+WV5dAiVb2w1lgf21Wz84Uuou1TwCJ+\
						ivxcpijobsHQLOLMakYSyRonH6SQJtL5CHXycBubA9sS7F2nVG2fMn6z9Ev11nu7J4IPPF9u\
						v / ZqwAIlXwxVPsl4K69rWmdP4i5ezj++I7nC + kX6qjxpcyhnQalKAl2OC8AMNEo0awIBEQ == ";

	StringSource strs(pub1, true);

	//"C:\Users\yan\source\repos\crytoTest\crytoTest\pub.pem"

	FileSource files("C:\\Users\\yan\\source\\repos\\crytoTest\\crytoTest\\pub.pem", true);
	RSA::PublicKey key;

	
	LoadPem(files, key);
	
	

	//RSAES_OAEP_SHA_Encryptor pubkey(key);
	//RSAES_OAEP_SHA256_Encryptor pubkey(key);
	RSAES_PKCS1v15_Encryptor encryptor(key);

	
	SecByteBlock sbbCipherText(encryptor.CiphertextLength(plain.size()));
	AutoSeededRandomPool rng;

	std::string cipher;
	StringSource ss1(plain, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(cipher)));


	////pubkey.Encrypt(rng, (byte const*)plain.data(), plain.size(), sbbCipherText.begin());

	////std::cout << sbbCipherText << std::endl;
	std::cout << cipher << std::endl;

	////std::cout << BytesToBase64((byte *)cipher.data(), cipher.size()) << std::endl;

	std::string encodedCipherText;

	StringSource ss(cipher, true, new Base64Encoder(new StringSink(encodedCipherText), false));

	std::cout << encodedCipherText << std::endl;

	//FileSink(encryptedFilename).Put(sbbCipherText.begin(), sbbCipherText.size());
}



int Test() {
	// Load a RSA public key
	FileSource fs1("pub.pem", true);
	RSA::PublicKey k1;
	PEM_Load(fs1, k1);

	std::cout << "load pub.pem fome file" << std::endl;
	const Integer& e = k1.GetPublicExponent();
	std::cout << e << std::endl;

	const Integer& n = k1.GetModulus();
	std::cout << n << std::endl;

	AutoSeededRandomPool prng;
	bool v = k1.Validate(prng, 2);
	if (!v)
		throw std::runtime_error("Failed to validate public key");

	std::cout << "load pub.pem fome file success" << std::endl;
	PEM_Type type = PEM_GetType(fs1);
	std::cout << "key type " << type << std::endl;

	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	InvertibleRSAFunction parameters;
	parameters.GenerateRandomWithKeySize(rng, 2048);

	RSA::PrivateKey privateKey(parameters);
	//RSA::PublicKey publicKey(parameters);
	RSA::PublicKey publicKey(k1);

	////////////////////////////////////////////////
	// Secret to protect
	static const int SECRET_SIZE = 10;
	//const char* code = "Yiri123456";
	//std::string plaintext = "Yiri123456";
	SecByteBlock plaintext(SECRET_SIZE);
	//memset(plaintext, 'A', SECRET_SIZE);
	plaintext[0] = 'Y';
	plaintext[1] = 'i';
	plaintext[2] = 'r';
	plaintext[3] = 'i';
	plaintext[4] = '1';
	plaintext[5] = '2';
	plaintext[6] = '3';
	plaintext[7] = '4';
	plaintext[8] = '5';
	plaintext[9] = '6';
	std::cout << plaintext << std::endl;
	////////////////////////////////////////////////
	// Encrypt
	RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

	// Now that there is a concrete object, we can validate
	assert(0 != encryptor.FixedMaxPlaintextLength());
	assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

	// Create cipher text space
	size_t ecl = encryptor.CiphertextLength(plaintext.size());
	assert(0 != ecl);
	SecByteBlock ciphertext(ecl);

	encryptor.Encrypt(rng, plaintext, plaintext.size(), ciphertext);

	std::cout << plaintext << " == " << ciphertext << std::endl;


	std::cout << "=======GenerateRSAKey==========" << std::endl;
	GenerateRSAKey(1024, "pub", "pri");

	return 0;

	////////////////////////////////////////////////
	// Decrypt
	RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

	// Now that there is a concrete object, we can check sizes
	assert(0 != decryptor.FixedCiphertextLength());
	assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

	// Create recovered text space
	size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
	assert(0 != dpl);
	SecByteBlock recovered(dpl);

	DecodingResult result = decryptor.Decrypt(rng,
		ciphertext, ciphertext.size(), recovered);

	// More sanity checks
	assert(result.isValidCoding);
	assert(result.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));

	// At this point, we can set the size of the recovered
	//  data. Until decryption occurs (successfully), we
	//  only know its maximum size
	recovered.resize(result.messageLength);

	// SecByteBlock is overloaded for proper results below
	assert(plaintext == recovered);

	std::cout << "Recovered plain text success" << std::endl;

}

void ValidCryptoLib()
{
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	std::string plain = "CBC Mode Test:Hello!";
	std::string cipher, recovered;

	std::cout << "plain text: " << plain << std::endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch (const Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	std::cout << "key: ";
	encoder.Put(key, key.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "iv: ";
	encoder.Put(iv, iv.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "cipher text: ";
	encoder.Put((const byte*)&cipher[0], cipher.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		std::cout << "recovered text: " << recovered << std::endl;
	}
	catch (const Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

int main(int argc, char* argv[])
{
	try
	{
		Encrypt2("Yiri123456");

	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	return 0;
}