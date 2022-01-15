# BusySleepBeacon

This is a simple project made to evade https://github.com/thefLink/Hunt-Sleeping-Beacons by using a busy wait instead of beacon's built in Sleep() call.  
Most of the structure e.g.  Sleep hook, shellcode exec etc. are taken from mgeeky's https://github.com/mgeeky/ShellcodeFluctuation.

## How it works

- A userland hook is applied to the Sleep() function called by beacon
- Beacon calls Sleep() to sleep
- The hook redirects execution to our sleep function
- Our sleep function performs the sleep using a busy wait
- Execution is passed back to the beacon shellcode

This way, we intercept and replace the Sleep() call with our busy wait function, preventing the thread from entering the DelayExecution state.  
There is a possible OPSEC implication of this implementation in that it uses considerably more CPU than a normal beacon. Be aware of that.

## Usage
### Use busy sleep
main.exe ./beacon.bin 1
### No busy sleep
main.exe ./beacon.bin 0

### Test detection
Hunt-Sleeping-Beacons.exe

Expected results:

![](https://i.imgur.com/OMgMQMa.png)
![](https://i.imgur.com/fxyvbtL.png)
