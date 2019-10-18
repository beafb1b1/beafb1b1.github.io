# ciscn 2018 daysbank
[https://github.com/beafb1b1/challenges/tree/master/ciscn/2018_daysbank](https://github.com/beafb1b1/challenges/tree/master/ciscn/2018_daysbank)

(其他人的wp)[https://www.jianshu.com/p/993b513dca97]

首先我们需要逆向逻辑，准备A和B两个账号，并分别使用两个账号获取gift和profit。主要gift和profit各只能获取一次，并且有严格的逻辑先后顺序。

Gift和profit后，因为逻辑检查不严格，将会拥有转账权限，此时我们使用第一个transfer，将账号2的balance转给账号1。

账号1的balance变为4后，可以使用transfer2函数，此时，利用整型溢出，向账号2转账4以上的balance，那么账号1的balance将会变为极大。

然后payforflag即可。