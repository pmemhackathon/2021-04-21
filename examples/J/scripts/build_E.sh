#!/bin/bash -ex
#
# shell commands to build E_recordlog
#

if [ -z $JAVA_HOME ]; then
	JAVAC='javac'
else
	JAVAC=$JAVA_HOME/bin/javac
fi

$JAVAC -cp .:workshop/E_recordlog/llpl.jar workshop/E_recordlog/*.java
