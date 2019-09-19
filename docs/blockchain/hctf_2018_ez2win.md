# hctf 2018 ez2win

[https://github.com/beafb1b1/challenges/tree/master/hctf/HCTF2018_ez2win](https://github.com/beafb1b1/challenges/tree/master/hctf/HCTF2018_ez2win)

审计，发现存在如下函数
```
  function _transfer(address from, address to, uint256 value) {
    require(value <= _balances[from]);
    require(to != address(0));
    require(value <= 10000000);

    _balances[from] = _balances[from].sub(value);
    _balances[to] = _balances[to].add(value);
  }
```
可以未授权直接运行，而合约创建者有：
```
uint256 public constant INITIAL_SUPPLY = 20000000000 * (10 ** uint256(decimals));
```
这么多的token，直接trasfer到我的账户上，然后payforflag就行了。