lib_LTLIBRARIES=libotb.la
libotb_la_LDFLAGS = -version-info 0:0:0
libotb_la_SOURCES=asym-cipher.c bitkeeper.c friend.c io.c local-crypto.c memory.c openssl-util.c pad-db.c pad-rec.c protocol.c random.c settings.c sym-cipher.c unique-id.c user.c
if EXPORTABLE
libotb_la_SOURCES+=secure-using-real-openssl-functions.c
else
libotb_la_SOURCES+=insecure-using-dummy-replacements-of-the-original-openssl-functions.c
endif
libotb_la_LIBADD=$(libgio_CFLAGS) $(libglib_LIBS) $(libgobject_LIBS) $(libuuid_LIBS) $(openssl_LIBS)
AM_CPPFLAGS=$(libgio_CFLAGS) $(libglib_CFLAGS) $(libgobject_CFLAGS) $(libuuid_CFLAGS) $(openssl_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
