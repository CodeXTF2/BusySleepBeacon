# BusySleepBeacon

This is a simple project made to evade https://github.com/thefLink/Hunt-Sleeping-Beacons by using a busy wait instead of beacon's built in Sleep() call.  
Most of the structure e.g.  Sleep hook, shellcode exec etc. are taken from mgeeky's https://github.com/mgeeky/ShellcodeFluctuation.

## Usage
### Use busy sleep
main.exe ./beacon.bin 1
### No busy sleep
main.exe ./beacon.bin 0
