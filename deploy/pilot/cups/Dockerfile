# A real CUPS print server for the pilot.
#
# cups-pdf writes finished jobs to /var/spool/cups-pdf, so the acceptance run
# can verify what actually came off the printer rather than trusting the
# client's claim that it printed.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      cups cups-pdf cups-filters printer-driver-cups-pdf \
 && rm -rf /var/lib/apt/lists/*

COPY cupsd.conf /etc/cups/cupsd.conf
COPY start-cups.sh /usr/local/bin/start-cups.sh
RUN chmod +x /usr/local/bin/start-cups.sh

EXPOSE 631
VOLUME ["/var/spool/cups-pdf"]

ENV CUPS_QUEUE=hall-a
CMD ["/usr/local/bin/start-cups.sh"]
