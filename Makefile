<<<<<<< HEAD
xml2rfc ?= xml2rfc
kramdown-rfc2629 ?= kramdown-rfc2629

drafts := draft-piraux-tcp-ao-tls.txt
xml := $(drafts:.txt=.xml)
mkd := $(drafts:.txt=.md)

%.txt: %.md 
	$(kramdown-rfc2629) $< > $(patsubst %.txt,%.xml, $@)
	$(xml2rfc) $(patsubst %.txt,%.xml, $@) > $@

%.txt: %.xml
	$(xml2rfc) $< $@

%.html: %.xml
	$(xml2rfc) --html $< $@


all: $(drafts)

spell: $(mkd)
	mdspell -n -a --en-us -r $(mkd)
=======
LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
>>>>>>> 13a3773e730c84d1347a75744cf03966f88bf411
