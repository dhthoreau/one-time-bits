lib_LTLIBRARIES=libotb.la
libotb_la_LDFLAGS = -version-info 0:0:0
libotb_la_SOURCES=bitkeeper.c cipher.c friend.c io.c local-crypto.c openssl-util.c pad-db.c pad-rec.c random.c rsa.c settings.c smemset.c
if EXPORTABLE
libotb_la_SOURCES+=secure-using-real-openssl-functions.c
else
libotb_la_SOURCES+=insecure-using-dummy-replacements-of-the-original-openssl-functions.c
endif
libotb_la_LIBADD=$(libglib_LIBS) $(libgobject_LIBS) $(libuuid_LIBS) $(openssl_LIBS)
AM_CPPFLAGS=$(libglib_CFLAGS) $(libgobject_CFLAGS) $(libuuid_CFLAGS) $(openssl_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
