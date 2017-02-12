bin_PROGRAMS=one-time-bits-demo-app
one_time_bits_demo_app_SOURCES=app.c console.c create-user.c demo-user.c dialog.c edit-user.c main.c passphrase-unlock.c validation.c
one_time_bits_demo_app_LDADD=../../libotb/src/libotb.la $(libgtk_LIBS) $(libgmodule_LIBS)
AM_CPPFLAGS=$(libgtk_CFLAGS) $(libgmodule_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\" -DDATA_DIRECTORY=\"$(datadir)/one-time-bits-demo-app\"
