# ARP攻击之中间人攻击
	1.攻击者截获网关发给目标的ARP请求数据包，冒充目标的mac地址，给网关发送ARP应答包，更新网关ARP缓存，这样网关发给目标的数据包都会发给攻击者。同时避免ARP缓存被更新，每隔1s给网关发送一次ARP应答包。
	2.攻击者截获目标发给网关的ARP请求数据包，冒充网关的mac地址，给目标发送ARP应答包，更新目标ARP缓存，这样目标发给网关的数据包都会发给攻击者。同时避免ARP缓存被更新，每隔1s给目标发送一次ARP应答包。
	3.同时也要避免目标上不了网，攻击者必须将数据包转发，可以将/proc/sys/net/ipv4/ip_forward值改为1实现路由转发功能。
	
# cookie劫持
	要实现cookie劫持，首先要拿到cookie才行，也就是能够抓到其他主机的数据包。一般情况下只需要开启混杂模式就可以抓到，但是有些网卡只能抓到发给自己的数据包，很难抓到发给其他主机的数据包，所以这里借助ARP攻击之中间人攻击就很容易实现了。主要抓取的是HTTP数据包，取出其中的cookie数据，再用google插件cookie hacker进行劫持。这样就可以登录别人的帐号了，不过不要干坏事阿…………
