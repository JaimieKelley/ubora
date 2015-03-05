#!/bin/bash

if [ -f INSTALL_DIR ] 
    then 
    echo "INSTALL_DIR set"
    else
    echo `pwd` > INSTALL_DIR
fi
INSTALL_DIR=`cat INSTALL_DIR`

if [[ "$1" == "help" ]] 
then
    echo "Usage 1: start.sh minor [compile/run]"
    echo "Usage 2: start.sh major [compile/run]"
    echo "Usage 3: start.sh clean"
    echo "Usage 4: start.sh help (this screen)\n\n"
fi


if [[ "$1" == "clean" ]] 
then
    #First clean everything up
    echo "Cleaning up current version"
    echo "The may be many warnings or errors here.  Ignore"
    rm borgPro filterDown MITM qualRedis ipset.sh borg.cfg borg.cfp
    rm betterProp  lightningClient.class myServers hashfile so-far-seen uboraExtractAnswers.pl logAnswers.pl
    pkill -9 redis-server
    pkill filterDown
    /sbin/iptables --flush OUTPUT
    /sbin/iptables --flush INPUT
    $INSTALL_DIR/global.bin/killall.screens
    echo "FInished cleaning\n\n\n\n"
fi

if [[ "$1" == "minor" ]] 
then
    echo "Make sure Ubora screens are runnings"
    $INSTALL_DIR/global.bin/uboraScreens.pl
    if [[ "$2" == "compile" ]] 
    then
	echo "Compile Ubora Minor"
	cd $INSTALL_DIR/Minor/
	./makeWillow.sh
    fi
    cd $INSTALL_DIR
    cp $INSTALL_DIR/Minor/borgPro . 
    cp $INSTALL_DIR/Minor/borg.cfg .
    cp $INSTALL_DIR/Minor/borg.cfp .
    cp $INSTALL_DIR/Minor/filterDown . 
    cp $INSTALL_DIR/Minor/MITM  . 
    cp $INSTALL_DIR/Minor/qualRedis . 
    cp $INSTALL_DIR/Minor/hashfile .       
    grep targetnode ubora.conf | awk -F: '{gsub(/ /, "", $2); print $2}' > $INSTALL_DIR/mydisk
    screen -S filterDown  -p0 -X stuff $'./filterDown\n'
    screen -S redis  -p0 -X stuff $'redis-stable/src/redis-server redis-stable/redis.conf\n'
fi

if [[ "$1" == "major" ]] 
then
    echo "Label java as UboraReplayEngine"
    JAVA_EXEC=`which java`
    ln -s $JAVA_EXEC /bin/UboraReplayEngine
    echo "Make sure Ubora screens are runnings"
    $INSTALL_DIR/global.bin/uboraScreens.pl
    if [[ "$2" == "compile" ]] 
    then
	echo "Compile Ubora Minor"
	cd $INSTALL_DIR/Major/
	./makeAll.sh
    fi
    cd $INSTALL_DIR
    cp $INSTALL_DIR/Major/borgPro . 
    cp $INSTALL_DIR/Major/borg.cfg .
    cp $INSTALL_DIR/Major/borg.cfp .
    cp $INSTALL_DIR/Major/filterDown . 
    cp $INSTALL_DIR/Major/betterProp  . 
    cp $INSTALL_DIR/Major/ipset.sh .    
    cp $INSTALL_DIR/Major/hashfile .     
    cp $INSTALL_DIR/Major/betterProp .   
    cp $INSTALL_DIR/Major/lightningClient.class .
    cp $INSTALL_DIR/Major/uboraExtractAnswers.pl .
    cp $INSTALL_DIR/Major/logAnswers.pl .
    screen -S betterProp  -p0 -X stuff $'./betterProp\n'
    screen -S redis  -p0 -X stuff $'redis-stable/src/redis-server redis-stable/redis.conf\n'
fi

exit 

