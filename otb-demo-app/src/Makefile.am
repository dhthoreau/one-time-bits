bin_PROGRAMS=otbdemo
otbdemo_SOURCES=create-user.c main.c otb-demo-app.c
otbdemo_LDADD=../../libotb/src/libotb.la $(libgtk_LIBS) $(libgmodule_LIBS)
AM_CPPFLAGS=$(libgtk_CFLAGS) $(libgmodule_CFLAGS) -DLOCALEDIR=\""$(datadir)/locale"\"
