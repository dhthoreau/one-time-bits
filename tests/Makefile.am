TESTS=otb-tests
check_PROGRAMS=otb-tests
otb_tests_SOURCES=asym-cipher-tests.c bitkeeper-tests.c dummy-friend.c dummy-user.c friend-tests.c local-crypto-tests.c main.c pad-db-tests.c pad-rec-tests.c protocol-tests.c settings-tests.c sym-cipher-tests.c test-utils.c unique-id-tests.c user-tests.c
otb_tests_LDADD=../src/libotb.la $(libglib_LIBS) $(libgobject_LIBS) $(libuuid_LIBS) $(openssl_LIBS)
AM_CPPFLAGS=$(libglib_CFLAGS) $(libgobject_CFLAGS) $(libuuid_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
