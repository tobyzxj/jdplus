jdplus
======

京东智能云-智能硬件服务平台测试 

本软件暂时只支持`云家居`产品，`云健康`产品暂不支持

本软件用于测试JD+平台的RESTFUL API，供软硬件开发提供帮助

>开发文档详见: http://devsmart.jd.com/dev/api/home/index
>
>可能JD会修改API接口协议，发现问题请提**Issues**

## HOWTO

> 本软件使用[golang](http://golang.org/doc/install)开发，如需要使用`go`命令，请先搭建`go`运行环境

> **WINDOWS**: 请使用[Cygwin](http://www.cygwin.com/) 运行，获得更好体验

> **LINUX**: 请直接搭建`go`运行环境，使用`go run ...`命令启动

>在运行此命令前，你可能需要先安装如下第三方软件包
>
	 $ go get github.com/Unknwon/com
	 $ go get github.com/Unknwon/goconfig
	 $ go get github.com/bitly/go-simplejson 
	 $ go get github.com/tobyzxj/beego/httplib	 

1. 先成为[开发者](http://devsmart.jd.com/dev/index "JD+开发者")，并在开发者页面创建并发布一个产品,本软件需要在产品定义时定义以下两个参数：
	<table>
		<tr>
			<td>参数名称</td>
			<td>参数Id</td>
			<td>是否可控</td>
			<td>参数值类型</td>
		</tr>
		<tr>
			<td>温度</td>
			<td>temperature</td>
			<td>否</td>
			<td>float</td>
		</tr>
		<tr>
			<td>开关</td>
			<td>switch</td>
			<td>是</td>
			<td>string
				<table>
					<tr>
						<td>显示数据</td>
						<td>传输数据</td>
					</tr>
					<tr>
						<td>开</td>
						<td>1</td>
					</tr>
					<tr>
						<td>关</td>
						<td>0</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>


2. 再运行 `go run devsmart.go`(or `devsmart.exe`)，模拟一个硬件设备

    此时设备可以进行如下功能测试:
    * 发送心跳，维持设备和EventServer的SSL连接
    * 数据上传，可以模拟温度采集
    * 模拟一个开关，可以接受APP的远程控制

3. 再运行一个模拟APP的应用程序 `go run app-cli.go`(or `app-cli.exe`)

    此软件可以进行如下命令行操作 
	>需要输入回车才能执行命令
    * 查询设备在线或是离线
    * 查询当前的温度值
    * 远程控制设备开
    * 远程控制设备关
	
	<table>
	    <tr>
	        <td>功能列表</td><td>命令</td><td>简化命令</td>
	    </tr>
	    <tr>
	        <td>命令查询</td><td>list</td><td>l</td>
	    </tr>
	    <tr>
	        <td>设备激活</td><td>active</td><td>a</td>
	    </tr>
		<tr>
	        <td>查询设备在线或是离线</td><td>status</td><td>s</td>
	    </tr>
		<tr>
	        <td>查询当前的温度值</td><td>temperature</td><td>t</td>
	    </tr>
		<tr>
	        <td>远程控制设备开</td><td>switchon</td><td>son</td>
	    </tr>
		<tr>
	        <td>远程控制设备关</td><td>switchoff</td><td>soff</td>
	    </tr>
		<tr>
	        <td>退出应用</td><td>quit</td><td>q</td>
	    </tr>
	</table>

## LICENSE

**jdplus** is licensed under the Apache Licence, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0.html).