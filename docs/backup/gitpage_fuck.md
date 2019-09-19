# github pages采坑

## dev&master User Pages

gitpage分为两种，关于两种gitpage的说明可以参考：[https://help.github.com/en/articles/user-organization-and-project-pages](https://help.github.com/en/articles/user-organization-and-project-pages)

第一种叫Project Pages sites，这一种的话需要在master分支上开发代码，然后site会部署在gh-pages分支上。这种使用的url为```http(s)://<username>.github.io/<projectname>```这种模式。

另外一种叫User and Organization Pages sites，这一种需要在其他地方开发代码，然后将site推送到master分支上，gitpage会直接根据master分支建站。这种使用的url为```https://<username>.github.io```。

mkdocs这两种方式都支持，但是因为第一种方式需要后接一个projectname，所以我更倾向于第二种方式。但是第二种方式不能再master分支上创建代码，需要本地创建完成后才行，因为我新开了一个dev分支，并设定为默认分支，然后编辑完成后在本地编译到master分支上，这样就可以使用同一个项目完成这个站点（按照mkdocs官方的说法，需要弄两个项目才行，不推荐）。

## 操作记录

mkdocs的theme推荐mkdocs-material，建站方法非常简单，首先创立好项目，设定好master分支和dev分支，本地pip安装mkdocs和theme：
```bash
pip install mkdocs
pip install mkdocs-material
```

将dev分支clone下来，而后在目录执行：
```bash
mkdocs new myblog
```
将myblog目录内的内容拷贝出来，并把myblog目录删除（网上说直接在git的目录下new可能会出现git的问题）。

然后根据mkdocs-material的文档对配置文件和文档进行修改和编写：```https://squidfunk.github.io/mkdocs-material/```。

修改完成后，可以使用```mkdocs serve```在本机搭建查看。而后重点来了，因为我们在dev分支开发，而我们要推送到master分支，因此需要在部署的时候执行如下命令：
```mkdocs gh-deploy --remote-branch master```。

至此推送完成。另外推荐gittalk作为comment进行使用。
首先申请一个新的comment项目，之后使用gittalk的时候的每一个页面上的评论都是这个项目中的一个issue。

然后到```https://github.com/settings/applications/new```申请 clientID 和 clientSecret。

根据你的信息准备如下代码：
```htmlmixed
<h2 id="__comments">{{ lang.t("meta.comments") }}</h2>
<form id="gitalk-form" onsubmit="return false;">
    <div id="gitalk-container"></div>
</form>
<link rel="stylesheet" href="https://unpkg.com/gitalk/dist/gitalk.css">
<script src="https://unpkg.com/gitalk/dist/gitalk.min.js"></script>
<script src="https://cdnjs.loli.net/ajax/libs/blueimp-md5/2.10.0/js/md5.min.js"></script>
<script>
    const gitalk = new Gitalk({
        clientID: '', // add yourself's
        clientSecret: '', // add yourself's
        repo: 'comment',
        owner: '', // add yourself's
        admin: [''], // add yourself's
        id: md5(location.pathname),      // Ensure uniqueness and length less than 50
        distractionFreeMode: false  // Facebook-like distraction free mode
    })
    gitalk.render('gitalk-container')
</script>
```
到```your_python_path\Lib\site-packages\material\partials\integrations```中使用上述代码替换disqus.html中的代码。

最后重新运行```mkdocs gh-deploy --remote-branch master```即可。

可以使用hackmd对项目中的文档进行编辑，在```https://hackmd.io```中有一个版本选项可以从git中拉取文档和推送文档，需要注意的是，如果采取了这里使用的page，那么在拉取、修改、推送md后，需要在本地同步dev分支，然后再次运行```mkdocs gh-deploy --remote-branch master```指令推送到master分支，因为github是不会自动从你的dev分支编译到master分支的，这也是mkdocs较为麻烦的地方，如果使用了minimal-mistakes等theme的话就会方便一些，直接修改md文件即可。