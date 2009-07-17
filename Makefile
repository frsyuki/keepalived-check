
keepalived-check: keepalived-check.rb phraser.rb
	echo "#!/usr/bin/env ruby" > $@.tmp
	cat phraser.rb >> $@.tmp
	grep -v "require 'phraser'" < keepalived-check.rb >> $@.tmp
	chmod 755 $@.tmp
	if [ -f $@ ]; then mv $@ $@.old; fi
	mv $@.tmp $@

.PHONY: check clean

check: keepalived-check
	for f in test/*.conf.*; do \
		echo $$f; \
		ruby keepalived-check.rb -e $$f; \
		echo ""; \
	done

clean:
	rm -rf keepalived-check

