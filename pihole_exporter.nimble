# Package
version       = "0.1.0"
author        = "Nick"
description   = "Comprehensive Prometheus exporter for Pi-hole v6"
license       = "MIT"
srcDir        = "src"
bin           = @["pihole_exporter"]

# Dependencies
requires "nim >= 2.0.0"
