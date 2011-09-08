#! /bin/make -f
#
# @(#)$Info: Makefile for logscan. $
# @(#)$Id: GNUmakefile,v 2.5 2008/06/27 16:08:32 dcblack Exp $

TOOL=logscan
SRC=${TOOL}.pl ${TOOL}.asc
DOC=MANIFEST README INSTALLATION LICENSE HISTORY ${TOOL}.pdf
TAR=$(firstword $(wildcard $(foreach t,gtar tar,$(addsuffix bin/$t,/usr/local/ /usr/ /))))
PGP=63B82EB1
AUTHOR=David C Black

.PHONY: info help install sign sig tar

help:
	@perl -ne 'print if s/^#: //' GNUmakefile

info:
	@echo "TAR='${TAR}'"

#: help
#: install -- install in home bin
#: sign -- provide PGP signature
#: tar -- create tar file for distribution
#: logscan.pl

install: ${SRC}
	cp ${SRC} ${HOME}/bin

${TOOL}.asc: ${TOOL}.pl
	rm -f $@ ; gpg -o $@ -sab -u ${PGP} $<
	chmod a+r $@

VERSIONSCRIPT='next unless /${TOOL}.pl(?:,v)? ([0-9.]+)/; print $$1,"\n" ; exit'
tar: ${SRC}
	VER=$(shell perl -ne ${VERSIONSCRIPT} ${TOOL}.pl) ;\
	sleep 1                                           ;\
	cp ${TOOL}.pl ${TOOL}-$$VER                       ;\
	${TOOL}-$$VER -XT INSTALL                         ;\
	sleep 1                                           ;\
	cp ${TOOL}.asc ${TOOL}-$$VER.asc                  ;\
	${TAR} cvf ${TOOL}-$$VER.tar ${TOOL}-$$VER ${TOOL}-$$VER.asc ${DOC}

sign sig: ${SRC}
	rm -f README.asc;   gpg -sat -u ${PGP} README
	rm -f LICENSE.asc;  gpg -sat -u ${PGP} LICENSE
	rm -f MANIFEST.asc; gpg -sat -u ${PGP} MANIFEST

%.pdf: %.pl
	VER=$(shell perl -ne ${VERSIONSCRIPT} $*.pl);\
	pod2pdf \
          --title    $*-$$VER\
          --author   '${AUTHOR}'\
          --header   '$* User Manual'\
          --revision $$VER\
          --paper    usletter\
          --verbose  1\
          --podfile  $*.pl &&\
	mv $*.pl.pdf $*.pdf

# END OF Makefile
