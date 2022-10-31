from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A

d = DNSRecord(DNSHeader(qr=1, aa=1, ra=1),
              q=DNSQuestion("abc.com"),
              a=RR("abc.com", rdata=A("1.2.3.4")))
a = d