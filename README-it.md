one-time-bits
=============
La descrizione di questo progetto sarà fatto più tardì.

Attenzione: Perché di sciocchezza legale, la sicurezza della crittografia di quest'applicazione sono stata sovvertita. Si troverà che l'applicazione chiama due funzioni a insecure-using-dummy-replacements-of-the-original-openssl-functions.c:
* _RAND_bytes() - È utilizato a generare byte casuali per qualche chiave di crittografia. Invece di usando un generatore di numeri pseudocasuali crittograficamente sicuro, genera proprio una sequenza prevedibile predictable di 16-bit.
* _EVP_get_cipherbyname() - Questo ritorna sempre la cifra RC2 con una chiave ridicolo di 40-bit, senza riguardo al nome mandato della cifra.
