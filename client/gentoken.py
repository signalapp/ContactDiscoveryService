import sys, binascii, hmac, time, hashlib

if len(sys.argv) < 2:
  print("Usage: %s <username> <secret>" % sys.argv[0])
  sys.exit(1)

username = sys.argv[1]
secret   = binascii.unhexlify(sys.argv[2])

prefix = "%s:%s" % (username, int(time.time()))

mac = hmac.new(secret, prefix.encode(), digestmod=hashlib.sha256).digest()

print("%s:%s" % (prefix, binascii.hexlify(mac[0:10]).decode()))
