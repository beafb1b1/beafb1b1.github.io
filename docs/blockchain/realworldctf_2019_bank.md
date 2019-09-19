## 分析

题目代码和exp：[https://github.com/beafb1b1/challenges/tree/master/rwctf/2019_bank](https://github.com/beafb1b1/challenges/tree/master/rwctf/2019_bank)

schnorr签名，关键问题在这里：
```python
req.sendall("Please send us your signature")
msg = self.rfile.readline().strip().decode('base64')
print balance
print "gggggggg"
print "verify's pubkey",point_add(userPk, pk)
if schnorr_verify('WITHDRAW', point_add(userPk, pk), msg) and balance > 0:
    print "flag!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    req.sendall("Here is your coin: %s\n" % FLAG)
print "gggggggg"
```
这里直接对用于提供的公钥和服务器提供的公钥进行了加法，所以这里可以实施Rogue attack，原理很简单，因为我们不知道point_add(userPk, pk)后的私钥是什么，我们只知道userPk对应的私钥，那么我们可以构造rogue_userPk=userPk-pk, 虽然我们也不知道rogue_userPk的私钥，但是不需要知道，服务器接收到rogue_userPk后会进行rogue_userPk+pk作为公钥进行认证，这里rogue_userPk+pk=userPk，私钥已知，所以可以进行签名。那么问题的关键是如何构造对应的point_sub，其实非常简单，椭圆曲线上的点取y轴对称的点相加就可以，也就是：
```python
def point_sub(p1, p2):
    newp2=(p2[0],-p2[1])
    return point_add(p1,newp2)
```

## exploit

```python
from zio import *
import os
import hashlib
from schnorr import *
import base64

target=("tcp.realworldctf.com",20014)
#target=("127.0.0.1",20014)
io=zio(target, print_read = COLORED(REPR, 'red'), print_write = COLORED(REPR, 'blue'), timeout = 100000)

def pass_proof(io):
    io.read_until("starting with ")
    start=io.readline().strip()
    while True:
        end=os.urandom(5)
        if hashlib.sha1(start+end).hexdigest()[-4:]=="0000":
            io.write(start+end)
            return


pass_proof(io)

io.read_until("Please tell us your public key:")
mysk, mypk = generate_keys()
print mysk
print mypk
send_pubkey=base64.b64encode(str(mypk[0])+","+str(mypk[1]))
io.writeline(send_pubkey)

io.read_until("first priority!")
io.writeline("3".encode("base64").strip())
io.read_until("himself as one of us: (")
getpubkey=io.read_until(")").split(",")
pubkey=(int(getpubkey[0].replace("L","")),int(getpubkey[1].split("L")[0]))
print pubkey

io.read_until("Please tell us your public key:")
io.writeline(send_pubkey)
io.read_until("our first priority!")
io.writeline("1".encode("base64").strip())
io.read_until("Please send us your signature")
io.writeline(base64.b64encode(schnorr_sign("DEPOSIT", mysk)))

io.read_until("Please tell us your public key:")
roguepk=point_sub(mypk,pubkey)
send_roguepubkey=base64.b64encode(str(roguepk[0])+","+str(roguepk[1]))
io.writeline(send_roguepubkey)
io.read_until("our first priority!")
io.writeline("2".encode("base64").strip())
io.read_until("Please send us your signature")
io.writeline(base64.b64encode(schnorr_sign("WITHDRAW", mysk)))

#Here is your coin: rwctf{P1Ain_SChNorr_n33Ds_m0re_5ecur1ty!}
io.interact()
```
