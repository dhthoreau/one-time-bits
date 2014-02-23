TESTS=otb-tests
check_PROGRAMS=otb-tests
otb_tests_SOURCES=asym-cipher-tests.c cipher-tests.c friend-tests.c local-crypto-tests.c main.c pad-db-tests.c pad-rec-tests.c settings-tests.c test-utils.c
otb_tests_LDADD=../src/libotb.la $(libglib_LIBS) $(libgobject_LIBS) $(libuuid_LIBS) $(openssl_LIBS)
AM_CPPFLAGS=$(libglib_CFLAGS) $(libgobject_CFLAGS) $(libuuid_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
