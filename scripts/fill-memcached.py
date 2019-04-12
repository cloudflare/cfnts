import memcache
import time
import math

print "filling memcache"
servers = ["localhost:11211"]
mc = memcache.Client(servers)
rand = open("/dev/urandom", "rb")

interval = 3600
now = int(math.floor(time.time()))
for i in range(-50, 4):
    epoch = int((math.floor(now/interval)+i)*interval)
    key = "/nts/nts-keys/%s"%epoch
    print key
    if mc.set(key, rand.read(16)) == 0:
        print "failure"
    else:
        print "success"
