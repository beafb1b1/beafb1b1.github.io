# ByteCTF 2019 bet & hf

[bet](https://github.com/beafb1b1/challenges/tree/master/bytectf/bet_blockchain_bibi)

[hf](https://github.com/beafb1b1/challenges/tree/master/bytectf/hf_blockchain_bibi)

## bet

本题目是一个以太坊智能合约题目

首先需要进行evm的逆向，逆向出整体程序功能

首先我们想要payforflag，需要有10w余额
```js
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        emit SendFlag(b64email);
}
```
可以逆向出一个存钱函数和一个空投函数
```js
    function deposit() payable{
        uint geteth=msg.value/1000000000000000000;
        balanceOf[msg.sender]+=geteth;
    }
    
    function profit() {
        require(gift[msg.sender]==0);
        gift[msg.sender]=1;
        balanceOf[msg.sender]+=1;
}
```

还有一个betgame
```js
    function betgame(uint secretguess){
        require(balanceOf[msg.sender]>0);
        balanceOf[msg.sender]-=1;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
            isbet[msg.sender]=1;
        }
}
```

只要能够猜对secret 我们就可以用1个token bet出来2个token

Secret可以通过直接读取链上信息获得，也可以利用如下漏洞进行修改

```js
    function Bet() public{
        owner = msg.sender;
}
```

这里存在构造函数失控问题，通过执行Bet方法可以修改owner

修改owner后可以执行set secret方法

```js
    function setsecret(uint secretrcv) only_owner {
        secret=secretrcv;
}
```

然后我们使用profit可以获得1个token
接下来执行betgame方法，可以获得两个token 并且把msgsender的isbet标志位变为1

因为我们已经是owner了 所以可以执行doublebetgame方法，在这里如果我们只有1个token的话，可以通过故意bet失败的方式，实现整形溢出

```js
    function doublebetgame(uint secretguess) only_owner{
        require(balanceOf[msg.sender]-2>0);
        require(isbet[msg.sender]==1);
        balanceOf[msg.sender]-=2;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
        }
}
```

但是因为isbet标志位的问题，我们现在有两个token，所以我们可以再次执行一次betgame并故意输掉1个token，让我们的token数量保持在1从而执行doublebetgame实现溢出。最后payforflag

## hf

以太坊智能合约题目，首先需要对evm进行逆向。

目标是执行payforflag。

首先有一个空投函数：
```js
    function profit() public{
        require(gift[msg.sender]==0);
        gift[msg.sender]=1;
        balanceOf[msg.sender]+=1;
    }
```

然后我们向合约的转账会变成我们的余额
```js
    function hfvote() public payable{
        uint geteth=msg.value/1000000000000000000;
        balanceOf[msg.sender]+=geteth;
}
```
漏洞在ubw函数中：

```js
    function ubw() public payable{
        if (msg.value < 2 ether)
        {
            node storage n = node0;
            n.nodeadress=msg.sender;
            n.nodenumber=1;
        }
        else
        {
            n.nodeadress=msg.sender;
            n.nodenumber=2;
        }
}
```

函数中的第二个分支不存在初始化，n在执行的时候会形成未初始化漏洞，那么只要我们进入第二个分支就会修改storage中的第一个值为我们的地址，第二个值为2
```js
    address secret;
    uint count;
	address owner;
```
第一个值为secret
因此通过未初始化漏洞我们可以执行onlySecret修饰的 fate函数，fate函数中存在整形溢出漏洞
```js
        require(balanceOf[msg.sender]-value>=0);
        balanceOf[msg.sender]-=value;
        balanceOf[to]+=value;
```
通过整形溢出，我们可以获得大量余额，然后payforflag即可获得flag：
```js
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        balanceOf[msg.sender]=0;
        owner.transfer(address(this).balance);
        emit SendFlag(b64email);
    }
```