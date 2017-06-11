#!/bin/sh
CC=$1
item=`$CC --print-file-name liblto_plugin.so`
if [ "$item" = "`basename $item`" ]
then
	list=`$CC --print-search-dirs | grep ^programs: | sed 's/^programs: *=//'`
	IFS=:
	for i in $list ;
	do
		if [ -e $i/liblto_plugin.so ]
		then
			echo `realpath $i`/liblto_plugin.so
			exit 0
		fi
	done
else
	if [ -e $item ]
	then
		echo $item
		exit 0
	fi
fi
exit 1
