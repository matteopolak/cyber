#!/bin/bash

# avoid recursively calling
if [[ $1 -ne 1 ]]; then
	# call this script, but ignore stderr
	# warnings from bash 4.2+ are printed when null bytes
	# are expanded in strings, which happens in this script
	# due to the memory dump. we don't care about the
	# warnings though, so they're safe to ignore here
	/bin/bash ./$0 1 2>/dev/null;

	exit;
fi

# get pid of CCSClient
PID=$(ps -aux | grep CCSClient -m 1 | sed -E 's/root\s+([0-9]+).*/\1/p' | head -1);

echo "Process ID of CCSClient is '$PID'";
echo "Waiting for CCSClient to cycle...";

# wait until "Icon=/opt/CyberPatriot/Icon.png" shows up
# when 'strace'ing the CCSClient process
#
# 'strace -p' lets us attach to a running process by pid
#
# 2>&1 pipes stderr into stdout, since all strace output
# is sent to stderr by default
#
# '-m 1' terminates grep execution after 1 match, since
# the stdout stream from strace will only end when the process
# exits (which, in this case, will not happen)
#
# we don't care about the output from this, it just needs to wait
# until it reaches this point since the unencrypted flags are
# only shown for around 60 seconds before being removed
# from memory until the next cycle
strace -p $PID 2>&1 | grep -Po "Icon=/opt/CyberPatriot/Icon\.png" -m 1;

echo "Cycled! Dumping memory and searching for flags...";

# create memory dump
gcore $PID > /dev/null 2>&1;

# print memory dump to stdout
# replace new lines with spaces (for grep)
# use look-ahead and look-behind regex assertion so only the flag name is kept
#		P = use Perl regex parser
#		a = treat binary file as text
#		o = only show matches
# move them all to flags.txt
cat core.$PID | tr '\n' ' ' | grep -Pao "(?<=<Check>     <CheckID>)\w+(?=<\/CheckID>)" > flags.txt

echo "Found flags! Piped them to 'flags.txt'";
echo "Attempting to find answers...";
echo "";

# loop through all lines in the flags.txt file
while read line; do
	# list all contents of the memory dump
	#
	# search for the flag in the file, NOT where we first found it,
	# list the byte offset at the start of the line, and only show the first match
	# then, only keep the numbers at the start of the line (the byte offset)
	offset=$(cat core.$PID | grep -Pa "(?<=\0\0\0\0)$line(?=\0\0\0\0)" --byte-offset -m 1 | grep -Pzo '^\d+' -m 1);

	# use 'tail' on the same memory dump file, but skip all of the bytes
	# that come before the match from above
	#
	# search for '(?i)', which is a regex flag for matching case-insensitive text
	# CCS uses it for all of their regular expressions, so we can just return
	# the first regular expression that follows it, since the offset already skipped
	# everything that we don't care about
	match=$(cat core.$PID | tail -c +$offset | grep -Pzo "(?<=\(\?i\)).*" -m 1);

	# print out the flag and the possible answer
	echo "$line: $match";
done < flags.txt;

echo "";
echo "Possibly found some answers, they're most likely not 100% accurate.";
echo "I would recommend looking in './core.$PID' for more information.";
echo "NOTE: there are some unrelated answers in the file, but they're";
echo "usually prefixed by (?i) since they all use the case-insensitive";
echo "flag for their regular expressions.";
echo "";
echo "Here is a dump of (most) possible answers:";
echo "";

cat core.$PID | grep -Pao --color=never "(?<=\(\?i\))[^\0]+";