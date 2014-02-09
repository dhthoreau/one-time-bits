one-time-bits
=============
Decsription of this project TBD.

Note: Due to legal silliness, the encryption security in this program has been subverted. You will find that the program calls two functions in insecure-using-dummy-replacements-of-the-original-openssl-functions.c:
* _RAND_bytes() - This is used to generate random bytes for certain encryption keys. Instead of using a cryptographically-secure random number generator, it just returns a predictable 16-bit sequence.
* _EVP_get_cipherbyname() - This will always return the RC2 cipher using a paltry 40-bit key, regardless of the cipher name passed into it.
