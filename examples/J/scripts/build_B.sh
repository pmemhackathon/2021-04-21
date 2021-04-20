#!/bin/bash -ex
#
# shell commands to build B_anyintarray
#

if [ -z $JAVA_HOME ]; then
	JAVAC='javac'
else
	JAVAC=$JAVA_HOME/bin/javac
fi

$JAVAC -cp .:llpl.jar workshop/B_anyintarray/*.java workshop/util/*.java
