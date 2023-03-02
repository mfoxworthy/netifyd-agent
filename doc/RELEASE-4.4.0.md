## Bug Fixes

- Properly handle interface down events for PCAP capture threads.
- Don't flag the category JSON file as a configuration file.
- Don't clear device addresses until afer plugins have been called.
- Enabled application lookups for DNS hostnames.  IP-block lookups for DNS addresses remains disabled (https://gitlab.com/netify.ai/public/netify-agent/-/issues/57).
- Fixed duplicate risks being added to DNS flows (after a reset).
- Fixed bug where custom domains were not being searched (walked) properly.
- Fixed early DNS/LLMNR packet processing.
- Throw exception instead of silently ignoring invalid bucket IDs.
- Fixes for builds with plugin and/or netlink support disabled.
- Fixed offline playback flow discrepancy issue (https://gitlab.com/netify.ai/public/netify-agent/-/issues/48, https://gitlab.com/netify.ai/public/netify-agent/-/issues/59).
- Fixed crash-on-flow-purge when detection thread(s) terminate.
- Fixed several crash-on-exit bugs.
- Fixed various integer casts.
- Fixed divide-by-zero error.
- Fixed dump category (application & protocol were reversed).
- Don't overwrite soft-dissector protocol IDs.
- Fixed protocol "twins" logic (use detected_protcol directly).

## Improvements

- Upgraded to [JSON for Modern C++](https://github.com/nlohmann/json) v3.11.2
- Added the Agent version to `agent_hello` and `agent_status` JSON structures (https://gitlab.com/netify.ai/public/netify-agent/-/issues/61).
- Refactored devices endpoints / device addresses.
- Removed old ethers loader.
- Updated stats plugin interface to support interfaces and devices.
- Added new risk: HTTP Obsolete Server
- Added detetion event type for detection plugins.
- Added detection_updated to flow criteria expressions.
- Added a "non-strict" (non-RFC) hostname copy/sanitize mode for mDNS PTR "domain names".
- Restored extraction of mDNS "answers" (PTR domain name types).
- Appeased many compiler warnings.
- Packet processing performance improvements:
  * Flow Map Bucket size is now externally configurable.
  * Default Flow Map Bucket size increased from 100 to 128.
  * Flow Map Bucket is now locked from Lookup to Insert (incase we get a packet from an unexpected interface instance: TPACKETv3).
  * TPACKETv3 fanout mode and flags are now externally configurable.
  * Capture read timeout for PCAP and TPACKETv3 capture modes is now externally configurable.
  * Detection packet counter is now atomic.
  * Added atomic counter for TCP FIN ACKs.
  * Unified PCAP & TPACKETv3 read timeout default value.
  * Now tracking discarded packet bytes from TPACKETv3 capture type.
  * Redesign / optimized flow expiry and purge logic for larger flow counts (> 500,000+).
  * Fixed bug in pkt stats collection for TPACKETv3 interface instances.
- Refreshed external buildroot files.
- Improved flow detection and expiry logic.
- Added AVAST protocol/application twin: netify.avast
- Added Line protocol/application twin: netify.line
- Added Syncthing protocol/application twin: netify.syncthing
- Added TiVo/Connect protocol/application twin: netify.tivo
- Added Tuya/LP protocol/application twin: netify.tuya-smart
- Added ZOOM protocol/application twin: netify.zoom
- Redesigned the flow management and DPI queue logic.
- Further reduced Agent shutdown time.
- Added additional debug values to scoreboard (packets filtered, dropped, and loss as a percentage of all "raw" packets).
- Eliminated packet copying into DPI queue.
- Updated to [nDPI v4.6 Stable](https://github.com/ntop/nDPI/releases/tag/4.6)

## New Features

- Added interface status information to `netifyd --status` output (https://gitlab.com/netify.ai/public/netify-agent/-/issues/62).
- Added agent version to run-time JSON status (usually `/run/netifyd/status.json`) (https://gitlab.com/netify.ai/public/netify-agent/-/issues/61).
- Introduced device endpoint "snapshots" for stats plugins.
- Added INIT/COMPLETE events for stats plugins.
- Added support for multiple flow serializers.
- Added custom ostream logging class.
- Added OS detection support for [Endian](https://www.endian.com/).
- Added support for FTP STARTTLS.
- Added unified ndAddr (address) class to store and perform common operations on any kind of network address (MAC/IPv4/IPv6).
- Introduced flow "ticket" system which defers certain operations while packets remain queued.
- Introduced unified ndInterface class.
- Implemented support for [TPACKETv3](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt).
- Implemented support for TPACKETv3 "fanout" mode.  It is now possible to specify the same interface multiple times to enable parallel processing from the same interface.
- Added option to toggle the loading of custom domains.
- Added log file overwrite mode.

## New Protocols

- AVAST
- CryNetwork
- ElasticSearch
- FastCGI
- KISMET
- Line Calls
- Meraki Cloud
- Munin
- NAT Port Mapping Protocol, [NAT/PMP](https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol).
- Syncthing
- TP-Link Smart Home
- Tailscale
- TiVo/Connect
- Tuya/LP

# Deprecated Protocols

- Aimini
- AppleJuice
- Ayiya
- Direct Download Link
- DirectConnect
- FastTrack
- Fiesta
- Florensia
- OpenFT
- SOPcast
- Shoutcast
- StealthNet
- Thunder
