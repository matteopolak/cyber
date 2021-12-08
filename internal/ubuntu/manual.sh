#!/bin/bash

function update_time {
	NOW="[$(date +"%T")]";
}

function logger {
	local MESSAGE="$1";
	local NEW_LINE="\r";

	if [[ $2 -eq 0 ]]; then
		NEW_LINE="\n";
	elif [[ $2 -eq 2 ]]; then
		NEW_LINE="";
	fi

	update_time;
	printf "\33[2K $NOW $MESSAGE$NEW_LINE";
}

function find_by_type {
	local TYPE=$1;

	yes_no "Search for files of type '$TYPE'?";

	if [[ $FNRET -eq 1 ]]; then
		logger "Searching for files of type in home directories: $TYPE";
		find /home -name "*.$TYPE" 2>/dev/null;
	fi
}

function yes_no {
	local QUESTION=$1;
	local RESPONSE;
	local RESULT=0;

	logger "$QUESTION (Y/n): " 2;
	read -n 1 -r RESPONSE;

	if [[ "$RESPONSE" = "" ]]; then
		RESULT=1;
	elif [[ ${RESPONSE,,} = "y" ]]; then
		RESULT=1;
		echo "";
	else
		echo "";
	fi

	FNRET=$RESULT;
}

find_by_type mp3;
find_by_type mov;
find_by_type mp4;
find_by_type avi;
find_by_type mpg;
find_by_type mpeg;
find_by_type flac;
find_by_type m4a;
find_by_type flv;
find_by_type ogg;
find_by_type gif;
find_by_type png;
find_by_type jpg;
find_by_type jpeg;

echo "";
echo "  REMINDER: Look at the checklist!!!";
echo "";
