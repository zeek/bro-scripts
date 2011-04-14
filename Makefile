# This makefile is only meant to be used by Bro packagers to create
# a tarball of contributed scripts.  Resulting tarballs are named like:
#     bro-scripts-<date>.tar.gz

DATE=`date "+%Y%m%d"`
NAME="bro-scripts-$(DATE)"

all: dist

dist:
	mkdir $(NAME)
	cp *.bro README $(NAME)
	tar czf $(NAME).tar.gz $(NAME)
	rm -r $(NAME)

distclean:
	rm -r bro-scripts*
