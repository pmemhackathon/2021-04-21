#!/bin/bash -ex
#
# shell commands to build C_genericarray
#

if [ -z $JAVA_HOME ]; then
	JAVAC='javac'
else
	JAVAC=$JAVA_HOME/bin/javac
fi

$JAVAC -cp .:llpl.jar workshop/C_genericarray/*.java workshop/util/*.java
