#!/bin/bash

g++  -L/usr/local/lib borgc.cpp -o borgPro -std=c++0x -lhiredis -lipq -fopenmp  
g++  -L/usr/local/lib -std=c++0x betterPropagate.cpp -o betterProp -lhiredis  
javac -cp jedis-1.5.0.jar lightningClient.java 
