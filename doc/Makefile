POD = router2dns.pod router2dns.conf.pod

MAN1 = router2dns.1

MAN5 = router2dns.conf.5

HTML = $(POD:.pod=.html)

.SUFFIXES: .pod .html .pl

.SUFFIXES: .1 .5

HTMLROOT = /    # Change this to fix cross-references in HTML
POD2HTML = pod2html \
            --htmlroot=$(HTMLROOT) \
            --noindex

POD2MAN = pod2man \
	    --center=router2dns \
	    --release=0.3.7


all: doc

clean:
	rm -f pod2htm?.tmp
	rm -f $(MAN1) $(MAN5) $(HTML)

doc: $(POD) $(MAN1) $(MAN5) $(HTML)

.pod.1:
	$(POD2MAN) --section=1 $< $@

.pod.5:
	$(POD2MAN) --section=5 $< $@

.pod.html:
	$(POD2HTML) --infile=$< --outfile=$@
