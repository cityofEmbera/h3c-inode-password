# h3c-inode-password
Automatically exported from code.google.com/p/h3c-inode-password

适用于Windows系统，可以读取H3C iNode客户端已保存的密码。

原作者已不可考证，源于当初在一个论坛上发现的ParaseH3C.rar （现在Google和Baidu都找不到那个帖子了，如果原作者到此一游，请联系我，其实我C学的不好，都是照你的源代码格式改的，多谢你的源代码。） 其前端实现的不是很好，老是提示找不到H3C的安装路径，看了一下源代码，是读取了注册表HKLM\SOFTWARE\H3C下面的一个字符串值"EAD1XINSTALLPATH"，于是将前端稍加修改，传到这里，让大家都能看到。
