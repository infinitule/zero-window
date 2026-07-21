#!/bin/bash
# Start CUPS and create the pilot queue backed by the PDF backend.
set -euo pipefail

QUEUE="${CUPS_QUEUE:-hall-a}"
mkdir -p /var/spool/cups-pdf
chmod 1777 /var/spool/cups-pdf

# cups-pdf writes to the spool directory rather than to an anonymous user
# home, so the acceptance run can find the finished jobs.
cat > /etc/cups/cups-pdf.conf <<'CONF'
Out /var/spool/cups-pdf
AnonDirName /var/spool/cups-pdf
AnonUser nobody
Cleanup 0
Truncate 64
DecodeHexStrings 1
CONF

cupsd
# Wait for the scheduler rather than sleeping a fixed interval.
for _ in $(seq 1 50); do
  if lpstat -r >/dev/null 2>&1; then break; fi
  sleep 0.2
done

lpadmin -p "$QUEUE" -E -v cups-pdf:/ -m lsb/usr/cups-pdf/CUPS-PDF_opt.ppd 2>/dev/null \
  || lpadmin -p "$QUEUE" -E -v cups-pdf:/ -m drv:///cupsfilters.drv/pwgrast.ppd 2>/dev/null \
  || lpadmin -p "$QUEUE" -E -v cups-pdf:/ -m everywhere
cupsenable "$QUEUE"
cupsaccept "$QUEUE"
lpoptions -d "$QUEUE"

echo "CUPS ready: queue '$QUEUE' at ipp://$(hostname):631/printers/$QUEUE"
lpstat -p "$QUEUE"

# cupsd went to the background; hold the container open and surface its log.
exec tail -f /dev/null
