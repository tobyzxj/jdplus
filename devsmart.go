// Copyright 2014 toby.zxj@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// smart device demo for JD+ test
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Unknwon/com"
	"github.com/Unknwon/goconfig"
	sjson "github.com/bitly/go-simplejson"
	"github.com/tobyzxj/beego/httplib"
)

// 定义JD+平台HTTP头
const (
	JDUserAgent    string = "User-Agent"
	JDPlusHeardKey string = "JDPlusHeardKey"
)

// 默认的User-Agent
var JDPlusUserAgentDefault = "JDPlus_devsmart_toby.zxj@gmail.com"

// 定义JD+开发平台信息
// 只有合法的开发平台信息和注册的产品信息才能和JD+平台进行数据交互
type JDPlusDevelopmentPlatform struct {
	RestApiUrl string                // 请求地址
	Header     map[string]string     // HTTP 头信息
	Product    JDPlusRegisterProduct // 注册的产品信息
	Device     Device                // 设备参数信息
	SSLconfig  *tls.Config
}

// 产品定义
// 定义一个在JD+平台上已注册并发布的产品
type JDPlusRegisterProduct struct {
	Id     string `json:"product_id"`     // 厂商在创建一个“产品”时，由京东平台分配，唯一标识一个“产品”
	Secret string `json:"product_secret"` // 与product_id一起分配给厂商，作为以后设备认证秘钥
}

// 设备定义
// 定义个设备,具体该设备有哪些参数属性需要用户自己修改
// 这里定义了两个参数, 与 stream_id 对应
// 1. 开关 --> switch --> 可控 --> string
//     开 --> "1"
//     关 --> "0"
// 2. 温度 --> temperature --> 不可控
type Device struct {
	Id          string   `json:"-"`          // 设备Id
	FeedId      string   `json:"feed_id"`    // 京东平台对设备的唯一标识，与access_key一起控制app与设备之间的数据交换。（由京东平台分配）
	Accesskey   string   `json:"accees_key"` // 用户/设备进行数据访问的权限，与feed_id一起控制app与设备之间的数据交换。（由京东平台分配）,此API有笔误必须是accees_key,JD+问题
	Switch      string   `json:"-"`          // 参数1, 开关量
	Temperature string   `json:"-"`          // 参数2, 温度值
	EventServer []string `json:"-"`          // 设备需要连接的事件服务器
}

// 激活设备
// 该json包为激活一个设备时使用
type DeviceActive struct {
	Did string `json:"device_id"`  // 设备ID 厂商对设备的唯一识别，由厂商自己确定，同一个“产品”中的device_id不能有重复
	Pid string `json:"product_id"` // 产品ID
}

// 数据点
// 该json包在上传数据和查询数据时使用
type DataPoint struct {
	At    string `json:"at"`    // 数据采集的时间点
	Value string `json:"value"` // 数据值，实际使用时需要可以修改为注册产品定义变量时，和变量类型一致，string/float/int
}

// 数据流节点
// 该json在数据上传和下载时使用
type Stream struct {
	Id         string      `json:"stream_id"`  // 对应于在创建产品时的参数Id
	DataPoints []DataPoint `json:"datapoints"` // 数据点数组
}

// 多个数据流
// 一个请求可以上传或下载多个数据流
type Streamslice struct {
	Streams []Stream `json:"streams"`
}

// 设备控制数据包
// 该json用于设备控制
type ControlCommand struct {
	StreamId     string `json:"stream_id"`     // 控制变量，对应于创建产品是的控制参数Id
	CurrentValue string `json:"current_value"` // 控制命令
	AtTime       string `json:"at"`            // 控制命令生成的时间点
}

// 多个设备控制数据包
// 该json适用于具有多个控制参数的设备
type ControlCommandslice struct {
	ControlCommands []ControlCommand `json:"commands"`
}

// 用户需要指定的信息
type UserDefineInfo struct {
	DeviceId      string               // 需要操作的设备Id, 有用户自定义，保证唯一即可
	ProductId     string               // 产品号（Product_ID）, 在创建产品并发布后可以看到
	ProductSecret string               // 产品密钥（Product_secret）, 在创建产品并发布后可以看到
	ConfigFile    *goconfig.ConfigFile // 配置文件
}

// 修改成你自己的信息
// 如果定义了conf.d/jdplus.conf,则应用程序会自动从配置文件中读取
var config = UserDefineInfo{
	DeviceId:      "00000001",
	ProductId:     "51",
	ProductSecret: "MWmqJo3OgV4xJYlC3TJNNjrazx98CiRTxZYkAjib7fHYJmSn",
}

// 全局 JD+平台信息
// 包含了索要操作的设备
// 该演示版本只支持一个设备的操作
// 用户可以修改可以支持多设备的操作
var jdplus JDPlusDevelopmentPlatform

// heartbeat
type DeviceHeartbeat struct {
	Code int    `json:"code"`
	Dev  Device `json:"device"`
}

//
// {
//     "code": 1002,
//     "control": "xxxxxxxxx" //透传的控制命令,经过了URI编码
//     "feed_id" 28
// }
type DeviceControlCommand struct {
	Code    int64            `json:"code"`
	Control []ControlCommand `json:"control"`
	FeedId  int64            `json:"feed_id"`
}

// 设备控制响应JSON
// {
//     "code" : 102,
//     "result" : 0
//     "control_resp" : "xxxxxxx" //设备响应服务器
//     "device": {
//         "feed_id": "xxxxxxx",
//         "accees_key": "xxxxxxx"
//     }
// }
type DeviceControlReply struct {
	Code        int64                  `json:"code"`
	Result      int64                  `json:"result"`
	ControlResp DeviceControlReplyInfo `json:"control_resp"`
	Dev         Device                 `json:"device"`
}

// 设备控制反馈信息
// 用户可以自定义需要反馈给服务器的信息
type DeviceControlReplyInfo struct {
	Info string `json:"info"`
}

// 平台初始化
func init() {
	// Load X509 Key Pair
	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		fmt.Println("client: loadkeys: %s", err)
		os.Exit(0)
	}

	// 定义JD+平台信息
	jdplus.RestApiUrl = "https://apismart.jd.com/v1/"
	jdplus.Header = make(map[string]string)
	jdplus.Header[JDUserAgent] = "User-Agent"
	jdplus.Header[JDPlusHeardKey] = "JD-Key"
	jdplus.Product.Id = config.ProductId
	jdplus.Product.Secret = config.ProductSecret
	jdplus.Device.Id = config.DeviceId
	jdplus.SSLconfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	// 检测是否有conf.d/jdplus.conf配置文件
	// 如果有则使用配置文件的信息替换默认配置值
	if com.IsExist("conf.d/jdplus.conf") {
		fmt.Println("detect a config file")
		err = LoadConfig("conf.d/jdplus.conf")
		if err != nil {
			fmt.Println("read config file err", err)
			os.Exit(0)
		}
	}
}

// 模拟一个硬件设备
// 可以进行如下功能测试:
//     > 发送心跳，维持设备和EventServer的SSL连接
//     > 数据上传，可以模拟温度采集
//     > 模拟一个开关，可以接受APP的远程控制
func main() {
	// 读取用户自定义的参数，而不使用默认参数
	// argv0 --> not used
	// argv1 --> DeviceId
	// argv2 --> ProductId
	// argv3 --> ProductSecret
	argv := os.Args
	for k, v := range argv {
		switch k {
		case 0:
		case 1:
			if len(v) != 0 {
				config.DeviceId = v
			}
		case 2:
			if len(v) != 0 {
				config.ProductId = v
			}
		case 3:
			if len(v) != 0 {
				config.ProductSecret = v
			}
		default:
			// 参数太多
			fmt.Println("too many parameter")
			os.Exit(0)
		}
	}
	fmt.Println("\033[32mStart APP...\033[0m")
	fmt.Println("\033[32m[LocalTime]\033[0m:", time.Now().Format("2006-01-02T15:04:05-0700"))
	fmt.Println("\033[32m[Default DeviceId]\033[0m:", config.DeviceId)
	fmt.Println("\033[32m[ProductId]\033[0m:", config.ProductId)
	fmt.Println("\033[32m[ProductSecret]\033[0m:", config.ProductSecret)

	// 用户可以在此重新定义一个独立的设备，并对此设备进行操作
	var pudev *Device
	pudev = nil

	// var UserDev Device
	// UserDev.Id = "00000002"
	// pudev = &UserDev
	if pudev != nil {
		fmt.Println("Operator USER's device")
	} else {
		fmt.Println("Operator DEFAULT's device")
	}

	// 设备激活
	// 软件第一次运行会自动激活设备
	var trytimes int = 0
	for {
		err := jdplus.Active(pudev)
		trytimes++
		if err == nil {
			fmt.Println("\033[32m[INFO] Device active succeed\033[0m")
			break
		}
		fmt.Println("\033[31m[ERR] Device active failed\033[0m")

		// 在5秒后重试重新激活
		if trytimes > 3 {
			os.Exit(0)
		}
		time.Sleep(5 * time.Second)
	}

	// 设备需要
	// 1. 创建一个TLS连接到EventServer
	// 2. 维护这个连接，发送心跳，同时在此通道上进行数据收发（主要是控制命令）
	// 3. 独立创建一个线程用于定时长传采集温度数据
	go func() {
		c := make(chan string)

		var dev Device
		if pudev == nil {
			dev = jdplus.Device
		} else {
			dev = *pudev
		}

		for {
			fmt.Println("\033[32m[INFO]Srart to connect to EventServer...\033[0m")
			conn, err := jdplus.TLSConnect(pudev)
			if err != nil {
				fmt.Println("\033[31m[ERR]Connect to EventServer failed:\033[0m", err)
				time.Sleep(5 * time.Second)
				continue
			}
			defer conn.Close()

			// 打印TLS连接和服务器交互的SSL证书
			state := conn.ConnectionState()
			for _, v := range state.PeerCertificates {
				fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
				fmt.Println(v.Subject)
			}
			fmt.Println("client: handshake:", state.HandshakeComplete)
			fmt.Println("client: mutual:", state.NegotiatedProtocolIsMutual)

			// 创建一个任务线程
			// 在这里监控EventServer发来的数据
			// 一旦发现链路有问题则需要通知心跳线程关闭连接
			// 进行重新连接到EventServer
			go TLSConnectHandleThread(conn, c, dev)

			// 发送一个心跳
			fmt.Println("\033[32m[INFO]Start to send Heatbeat...\033[0m")
			err = SendHeartbeat(conn, dev)
			if err != nil {
				fmt.Println("\033[32m[INFO]Send Heatbeat err\033[0m")

				// 发送心跳错误，需要重新进行连接
				// 发送信号给网络读线程
				conn.Close()
				continue
			}
			fmt.Println("\033[32m[INFO]Send Heatbeat succeed\033[0m")

			// sleep 30s
			fmt.Println("Device sleep 30s")

		HeartBeat:
			for {
				select {
				case msg := <-c:
					fmt.Println(msg)
					if msg == "closed" {
						fmt.Println("Close this conn")
						conn.Close()
						break HeartBeat
					}

				case <-time.After(30 * time.Second):
					// 在这里维护心跳
					// 30 秒一次
					fmt.Println("\033[32m[INFO]Start to send Heatbeat...\033[0m")
					err := SendHeartbeat(conn, dev)
					if err != nil {
						fmt.Println("\033[32m[INFO]Send Heatbeat err\033[0m")

						// 发送心跳错误，需要重新进行连接
						// 发送信号给网络读线程
						conn.Close()
						break HeartBeat
					}
					fmt.Println("\033[32m[INFO]Send Heatbeat succeed\033[0m")

					// sleep 30s
					fmt.Println("Device sleep 30s")
				}
			}
		}
	}()

	// 设备定时上传采集数据
	// 15秒上传一次
	go func() {
		for {
			time.Sleep(15 * time.Second)
			fmt.Println("\033[32m[INFO]Start Updata temperature...\033[0m")
			err := jdplus.Updata(pudev)
			if err != nil {
				fmt.Println("\033[31m[ERR]Updata temperature failed\033[0m")
				continue
			}
			fmt.Println("\033[32m[INFO]Updata temperature succeed\033[0m")
		}
	}()

	// 退出软件
	for {
		fmt.Println("\033[32m use \"quit(q)\" to exit, JD+>> \033[0m")
		running := true
		reader := bufio.NewReader(os.Stdin)
		for running {
			data, _, _ := reader.ReadLine()
			cmd := strings.ToLower(string(data))
			switch cmd {
			case "quit":
				fallthrough
			case "q":
				fmt.Println("  \033[32mQuit\033[0m")
				os.Exit(0)
			}
		}
	}

	// stop here
	select {}
}

// 设备激活
func (this *JDPlusDevelopmentPlatform) Active(dev *Device) error {
	js := new(DeviceActive)
	if dev != nil {
		js.Did = dev.Id
	} else {
		js.Did = this.Device.Id
	}
	js.Pid = this.Product.Id
	data, err := json.Marshal(js)
	if err != nil {
		fmt.Println("json err:", err)
		return err
	}
	fmt.Println(string(data))

	req := httplib.Post(this.RestApiUrl + "device/activate").SetTLSClientConfig(this.SSLconfig)
	req.Debug(true)
	req.Header(this.Header[JDUserAgent], JDPlusUserAgentDefault)
	req.Header(this.Header[JDPlusHeardKey], this.Product.Secret)
	req.SetProtocolVersion("HTTP/1.1")
	req.Body(data)
	str, err := req.String()
	if err != nil {
		fmt.Println("req.string err:", err)
		return err
	}
	fmt.Println(str)

	// 分析服务器响应
	b, err := sjson.NewJson([]byte(str))
	if err != nil {
		fmt.Println("sjson err:", err)
	}
	code, _ := b.Get("code").String()
	if code != "200" {
		return errors.New("device active failed")
	}

	// feed_id & access_key
	feed_id, err := b.Get("data").Get("feed_id").String()
	if err != nil {
		return err
	}
	fmt.Println("feed_id:", feed_id)
	access_key, err := b.Get("data").Get("access_key").String()
	if err != nil {
		return err
	}
	fmt.Println("access_key:", access_key)
	server_ip, err := b.Get("data").Get("server_ip").StringArray()
	if err != nil {
		return err
	}
	fmt.Println("server_ip:", server_ip)
	if dev != nil {
		dev.FeedId = feed_id
		dev.Accesskey = access_key
		dev.EventServer = server_ip
	} else {
		this.Device.FeedId = feed_id
		this.Device.Accesskey = access_key
		this.Device.EventServer = server_ip
	}

	return nil
}

// 设备上传数据
func (this *JDPlusDevelopmentPlatform) Updata(dev *Device) error {
	feed_id := this.Device.FeedId
	// 重定向用户指定的设备
	if dev != nil {
		if len(dev.FeedId) != 0 {
			feed_id = dev.FeedId
		}
	}

	// create a request json for updata
	var ss Streamslice
	var s Stream
	var dp1, dp2 DataPoint
	dp1.At = time.Now().Format("2006-01-02T15:04:05-0700")
	dp1.Value = "12.9"
	dp2.At = time.Now().Format("2006-01-02T15:04:05-0700")
	dp2.Value = "13.2"
	s.Id = "temperature"
	s.DataPoints = append(s.DataPoints, dp1, dp2)
	ss.Streams = append(ss.Streams, s)
	data, err := json.Marshal(ss)
	if err != nil {
		fmt.Println("json err:", err)
		return err
	}
	fmt.Println("json is:", string(data))

	// updata
	req := httplib.Post(this.RestApiUrl + "feeds/" + feed_id).SetTLSClientConfig(this.SSLconfig)
	req.Debug(true)
	req.Header(this.Header[JDUserAgent], JDPlusUserAgentDefault)
	req.Header(this.Header[JDPlusHeardKey], this.Device.Accesskey)
	req.SetProtocolVersion("HTTP/1.1")
	req.Body(data)
	str, err := req.String()
	if err != nil {
		fmt.Println("req.string err:", err)
		return err
	}
	fmt.Println(str)

	// analysis back json
	b, err := sjson.NewJson([]byte(str))
	if err != nil {
		fmt.Println("sjson err:", err)
		return err
	}
	code, err := b.Get("code").String()
	if err != nil {
		return err
	}
	if code != "200" {
		return errors.New("Updata failed")
	}

	return nil
}

// 设备连接到EventServer
func (this *JDPlusDevelopmentPlatform) TLSConnect(dev *Device) (conn *tls.Conn, err error) {
	if dev == nil {
		dev = &this.Device
	}

	if len(dev.EventServer) == 0 {
		return nil, errors.New("Not found a EventServer")
	}

	for _, v := range dev.EventServer {
		conn, err = tls.Dial("tcp4", v, this.SSLconfig)
		if err != nil {
			fmt.Println("client dial err:", err, v)
			continue
		}
		return conn, nil
	}

	return nil, errors.New("Not found a EventServer can connect")
}

// LoadConfig loads configuration file.
func LoadConfig(cfgPath string) (err error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()

	if !com.IsExist(cfgPath) {
		os.Create(cfgPath)
	}

	// open config file
	config.ConfigFile, err = goconfig.LoadConfigFile(cfgPath)
	if err != nil {
		panic("    \033[31m[SYSERR] Fail to load configuration file: \033[0m" + err.Error())
	}

	// read user configuer
	// [base]
	jdplus.RestApiUrl, err = config.ConfigFile.GetValue("base", "apiuri")
	if err != nil {
		fmt.Println("    \033[31m[SYSERR] Fail to load configuration file: cannot find key base.apiuri\033[0m")
		return err
	}

	// [product]
	jdplus.Product.Id, err = config.ConfigFile.GetValue("product", "id")
	if err != nil {
		fmt.Println("    \033[31m[SYSERR] Fail to load configuration file: cannot find key product.id\033[0m")
		return err
	}
	jdplus.Product.Secret, err = config.ConfigFile.GetValue("product", "secret")
	if err != nil {
		fmt.Println("    \033[31m[SYSERR] Fail to load configuration file: cannot find key product.secret\033[0m")
		return err
	}

	// [device]
	jdplus.Device.Id, err = config.ConfigFile.GetValue("device", "id")
	if err != nil {
		fmt.Println("    \033[31m[SYSERR] Fail to load configuration file: cannot find key device.id\033[0m")
		return err
	}

	return err
}

// send a heatbeat to remote server
func SendHeartbeat(conn *tls.Conn, dev Device) error {
	var heartbeat DeviceHeartbeat
	heartbeat.Code = 101
	heartbeat.Dev = dev

	// creat a heartbeat
	js, err := json.Marshal(heartbeat)
	if err != nil {
		fmt.Println("json err:", err)
		return err
	}
	fmt.Println("Heartbeat:", string(js))

	// send to server
	conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(5)))
	n, err := conn.Write([]byte(string(js) + "\r\n"))
	if err != nil {
		fmt.Println("send hearbeat failed:", err)
		return err
	}
	fmt.Println("Heartbeat send succeed:", n)

	return nil
}

// 连接处理任务
// 此函数为一个任务
// 使用go启动
func TLSConnectHandleThread(conn *tls.Conn, c chan string, dev Device) {
	defer func() {
		fmt.Println("TLSConnectHandleThread Close")
	}()

	reply := make([]byte, 1024)
	var lightstatus bool = false
	for {
		// 如果连接为空则退出处理
		if conn == nil {
			fmt.Println("conn is nil")
			break
		}

		// 读取网络数据
		fmt.Println("read data form network")
		n, err := conn.Read(reply)
		if err != nil {
			fmt.Println("network read failed", err)
			if err == io.EOF {
				fmt.Println("read io.EOF")
				c <- "closed"
				break
			}
			c <- "closed"
			break
		}
		fmt.Println("EventServer feedback:", string(reply[:n]))

		// URI编码转换
		// 此设计个人觉得比较蛋疼，已经是使用RAW TCP在传输了，没有必要使用HTTP那一套
		// 设计成透传更好,二进制协议传输肯定比JSON文本传输好
		// 保留个人观点
		replystr, err := url.QueryUnescape(string(reply[:n]))
		if err != nil {
			fmt.Println("QueryUnescape err:", err)
			continue
		}
		fmt.Println("After QueryUnescape: ", replystr)

		// 处理响应
		var dcc DeviceControlCommand
		err = json.Unmarshal([]byte(replystr), &dcc)
		if err != nil {
			fmt.Println("json nmarshal err:", err)
			continue
		}
		fmt.Println(dcc)

		switch dcc.Code {
		case 1001:
			fmt.Println("this package is heartbeat")
		case 1002:
			fmt.Println("this package is control command")

			// 反馈给服务器，此命令我接收到了
			reply := new(DeviceControlReply)
			reply.Code = 102
			reply.Result = 0
			for _, v := range dcc.Control {
				if v.StreamId == "switch" {
					if v.CurrentValue == "1" {
						reply.ControlResp.Info = "light on ok"
						lightstatus = true
					} else {
						reply.ControlResp.Info = "light off ok"
						lightstatus = false
					}
				}

			}
			reply.Dev = dev
			js, err := json.Marshal(reply)
			if err != nil {
				fmt.Println("json err:", err)
				continue
			}
			fmt.Println("Command reply:", string(js))

			// send to server
			conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(5)))
			n, err := conn.Write([]byte(string(js) + "\r\n"))
			if err != nil {
				fmt.Println("Send command reply failed:", err)
				continue
			}
			fmt.Println("Command reply send succeed:", n)

			if lightstatus {
				fmt.Println("\033[32m[INFO]Ligth on\033[0m")
			} else {
				fmt.Println("\033[32m[INFO]Ligth off\033[0m")
			}

		default:
			fmt.Println("this package unknown")
		}
	}
}
