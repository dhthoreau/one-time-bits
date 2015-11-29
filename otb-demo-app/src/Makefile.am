bin_PROGRAMS=otbdemo
otbdemo_SOURCES=create-user-container.c main.c
otbdemo_LDADD=../../libotb/src/libotb.la $(libgtk_LIBS) $(libgmodule_LIBS)
AM_CPPFLAGS=$(libgtk_CFLAGS) $(libgmodule_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
