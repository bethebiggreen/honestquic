Quick Description for Modified 'proto-quic'
===========================================

Building on Linux
-----------------

1. Clone this repository:
   ```
   git clone https://github.com/bethebiggreen/honestquic.git
   cd honestquic/quic_sigcom_qoe_april/proto-quic_modified/
   export PROTO_QUIC_ROOT=$PWD/src
   export PATH=$PATH:$PWD/depot_tools
   export CHROMIUM_BUILDTOOLS_PATH=$PROTO_QUIC_ROOT/buildtools
   ```

2. Build the QUIC client, server, and tests:
   ```
   cd src
   gn gen out/Default && ninja -C out/Default quic_client quic_server
   ```

Newly Added Command Line Options
--------------------------------
1. (only quic_client) --iteration_num=1,2,3, ... N
   It indicates the number of request. 

2. (only quic_client) --unit=1 or 2 or 3
   A scale of time that elpased for downloading. 1 for milleseconds, 2 for microseconds and 3 for nanosecods unit.  

3. (only quic_client) --interval_msec=100
   The interval for assigned milleseconds between each iteration. 

4. --experiment_seq=1 or 2, ... Nth number
   Assigining sequence nummber in order to distinguish expermients. This number will be writeen in file name.
    
5. --using_honest_fatal=1 or 0
   HONEST_FATAL logs are suppressed by setting 0.


honest.conf 
-----------
1. honest.conf is read in run-time to set below parametres easily.
   ```
   DefaultMaxPacketSize 1350
   MaxPacketSize 1452
   MtuDiscoveryTargetPacketSizeHigh 1450
   MtuDiscoveryTargetPacketSizeLow 1430
   DefaultNumConnections 1
   PacingRate 1.25
   UsingPacing 1
   Granularity 100
   ```


