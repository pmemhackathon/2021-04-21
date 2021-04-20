#!/bin/bash -ex
#
# shell commands to build D_list
#

if [ -z $JAVA_HOME ]; then
	JAVAC='javac'
else
	JAVAC=$JAVA_HOME/bin/javac
fi

$JAVAC -cp .:llpl.jar workshop/D_list/*.java workshop/util/*.java
