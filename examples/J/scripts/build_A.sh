#!/bin/bash -ex
#
# shell commands to build A_intarray
#

if [ -z $JAVA_HOME ]; then
	JAVAC='javac'
else
	JAVAC=$JAVA_HOME/bin/javac
fi

$JAVAC -cp .:llpl.jar workshop/A_intarray/*.java workshop/util/*.java
