d1:target/manual.html
### CMDREF
target/cmdref.xml: doc/cmdref.src.xml
	xsltproc -V | echo
	dbproc --type=cmdref --src $? --out $@
target/manual.html: doc/*.x*l target/cmdref.xml
	dbproc --src doc/manual.xml --out - | xsltproc --output $@ doc/post.xsl -
target/usage.txt: target/manual.html
	lynx  -nolist -dump -width=80 $? | perl -ne "print if(/\S+/);"  > $@
### CMDREF
