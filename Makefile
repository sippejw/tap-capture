# Makefile, modified from PF_RING examples Makefile.in

#
# PF_RING
#
PFUTILSDIR = ./PF_RING/userland/examples

#
# Search directories
#
PFRING_KERNEL= ./PF_RING/kernel
INCLUDE    = -I${PFRING_KERNEL} -I${PFRING_KERNEL}/plugins -Ithird-party

#
# C compiler and flags
#
CC         = gcc
CFLAGS     =  -O2 -DHAVE_PF_RING -Wall ${INCLUDE} -DENABLE_BPF -D HAVE_PF_RING_ZC

#
# User and System libraries
#
DEBUG_OR_RELEASE = release
LIBS       =  -Ltarget/${DEBUG_OR_RELEASE} -ltap_capture -L/usr/local/lib -lpfring -lrt -ldl -lm -lssl -lcrypto -lpthread -lpcap

all: tap-capture
tap-capture.o: main.c
	${CC} ${CFLAGS} -c $< -o $@
rust-code:
	cargo build --${DEBUG_OR_RELEASE}
tap-capture: tap-capture.o ${LIBPFRING} rust-code
	${CC} ${CFLAGS} $< -o $@ ${LIBS}
clean:
	@rm -f tap-capture *.o *~
