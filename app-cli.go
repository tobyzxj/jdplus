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

// app demo for JD+ test
package main

import (
	"crypto/tls"
	//"crypto/x509"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	//"net/http"
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
	Accesskey   string   `json:"access_key"` // 用户/设备进行数据访问的权限，与feed_id一起控制app与设备之间的数据交换。（由京东平台分配）
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

// 模拟一个手机APP的应用程序
// 此软件可以进行以下操作
//        功能列表              命令            简化命令(需要输入回车符)
//   > 查询设备在线还是离线 --> status      --> s
//   > 查询当前的温度值     --> temperature --> t
//   > 控制远程设备开       --> switchon    --> son
//   > 控制远程设备关       --> switchoff   --> soff
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
	for {
		err := jdplus.Active(pudev)
		if err == nil {
			fmt.Println("\033[32m[INFO] Device active succeed\033[0m")
			break
		}
		fmt.Println("\033[31m[ERR] Device active failed\033[0m")

		// 在5秒后重试重新激活
		time.Sleep(5 * time.Second)
	}

	// 命令行处理
	go func() {
		fmt.Println("\033[32m==============================\033[0m")
		fmt.Println("\033[32mWelcome to toby's simple shell\033[0m")
		fmt.Println("\033[32m==============================\033[0m")
		running := true
		reader := bufio.NewReader(os.Stdin)
		for running {
			fmt.Printf("\033[32mJD+>> \033[0m")
			data, _, _ := reader.ReadLine()
			cmd := strings.ToLower(string(data))
			switch cmd {
			case "quit":
				fallthrough
			case "q":
				fmt.Println("  \033[32mQuit\033[0m")
				os.Exit(0)
			case "at":
				fmt.Println("  \033[32mOK\033[0m")

				// 设备手动激活
			case "active":
				fallthrough
			case "a":
				err := jdplus.Active(pudev)
				if err != nil {
					fmt.Println("  \033[31m[ERR] Device active failed\033[0m")
					break
				}
				fmt.Println("  \033[32m[INFO] Device active succeed\033[0m")

				// 查询设备在线还是离线
			case "status":
				fallthrough
			case "s":
				online, err := jdplus.Status(pudev)
				if err != nil {
					fmt.Println("  \033[31m[ERR]Check device err\033[0m", err)
					break
				}
				if online {
					fmt.Println("  \033[32m[INFO]Device is online\033[0m")
				} else {
					fmt.Println("  \033[32m[INFO]Device is offline\033[0m")
				}

				// 查询当前的温度值
			case "temperature":
				fallthrough
			case "t":
				fallthrough
			case "r":
				dp, err := jdplus.ReadData(pudev, "temperature")
				if err != nil {
					fmt.Println("  \033[31m[ERR]Read data err\033[0m", err)
					break
				}
				fmt.Println("  \033[32m[INFO]Device curent temperature is\033[0m", dp.Value, "at", dp.At)

				// 控制远程设备开
			case "switchon":
				fallthrough
			case "son":
				cmd := ControlCommand{
					StreamId:     "switch",
					CurrentValue: "1",
					AtTime:       time.Now().Format("2006-01-02T15:04:05-0700"),
				}
				cmds := make([]ControlCommand, 0)
				cmds = append(cmds, cmd)
				err := jdplus.SendControlCommand(pudev, cmds)
				if err != nil {
					fmt.Println("  \033[31m[ERR]switch on err\033[0m", err)
					break
				}
				fmt.Println("  \033[32m[INFO]switch on succeed\033[0m")

				// 控制远程设备关
			case "switchoff":
				fallthrough
			case "soff":
				cmd := ControlCommand{
					StreamId:     "switch",
					CurrentValue: "0",
					AtTime:       time.Now().Format("2006-01-02T15:04:05-0700"),
				}
				cmds := make([]ControlCommand, 0)
				cmds = append(cmds, cmd)
				err := jdplus.SendControlCommand(pudev, cmds)
				if err != nil {
					fmt.Println("  \033[31m[ERR]switch off err\033[0m", err)
					break
				}
				fmt.Println("  \033[32m[INFO]switch off succeed\033[0m")

				// 命令行列表
			case "list":
				fallthrough
			case "l":
				fmt.Println("  \033[32m------------------------\033[0m")
				fmt.Println("  \033[31mlist(l)\033[32m: list commands\033[0m")
				fmt.Println("  \033[31mquit(q)\033[32m: quit this app\033[0m")
				fmt.Println("  \033[31mat\033[32m: test command\033[0m")
				fmt.Println("  \033[31mactive(a)\033[32m: actice a device\033[0m")
				fmt.Println("  \033[31mstatus(s)\033[32m: check the status of device, offline or online\033[0m")
				fmt.Println("  \033[31mtemperature(t/r)\033[32m: query the current temperature of device\033[0m")
				fmt.Println("  \033[31mswitchon(son)\033[32m: turn on the switch of device, maybe a light\033[0m")
				fmt.Println("  \033[31mswitchoff(soff)\033[32m: turn off the switch of device, maybe a light\033[0m")

			default:
				fmt.Println("  \033[32mUnknown command\033[0m")
			}
			fmt.Println("")
		}
	}()

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

// 查询设备状态
// true 设备在线
// false 设备离线
func (this *JDPlusDevelopmentPlatform) Status(dev *Device) (bool, error) {
	feed_id := this.Device.FeedId
	device_id := this.Device.Id
	// 重定向用户指定的设备
	if dev != nil {
		if len(dev.FeedId) != 0 {
			device_id = dev.Id
			feed_id = dev.FeedId
		}
	}

	req := httplib.Get(this.RestApiUrl + "device/" + feed_id + "/status").SetTLSClientConfig(this.SSLconfig)
	req.Debug(true)
	req.Header(this.Header[JDUserAgent], JDPlusUserAgentDefault)
	req.Header(this.Header[JDPlusHeardKey], this.Device.Accesskey)
	req.SetProtocolVersion("HTTP/1.1")
	str, err := req.String()
	if err != nil {
		fmt.Println("req.string err:", err)
		return false, err
	}

	fmt.Println(str)

	// analysis back json
	b, err := sjson.NewJson([]byte(str))
	if err != nil {
		fmt.Println("sjson err:", err)
		return false, err
	}
	code, err := b.Get("code").String()
	if err != nil {
		return false, err
	}
	if code != "200" {
		fmt.Println("Get stream failed")
		return false, err
	}
	// 是否在线
	online, err := b.Get("data").Get("status").String()
	if err != nil {
		return false, err
	}
	if online == "1" {
		fmt.Println("device:", device_id, "is online")
	} else {
		fmt.Println("device:", device_id, "is offline")
		return false, nil
	}

	return true, nil
}

// 查询当前设备的传感器数据
func (this *JDPlusDevelopmentPlatform) ReadData(dev *Device, stream_id string) (dp DataPoint, err error) {
	feed_id := this.Device.FeedId
	// 重定向用户指定的设备
	if dev != nil {
		if len(dev.FeedId) != 0 {
			feed_id = dev.FeedId
		}
	}

	req := httplib.Get(this.RestApiUrl + "feeds/" + feed_id + "/streams/" + stream_id).SetTLSClientConfig(this.SSLconfig)
	req.Debug(true)
	req.Header(this.Header[JDUserAgent], JDPlusUserAgentDefault)
	req.Header(this.Header[JDPlusHeardKey], this.Device.Accesskey)
	req.SetProtocolVersion("HTTP/1.1")
	str, err := req.String()
	if err != nil {
		fmt.Println("req.string err:", err)
		return dp, err
	}

	fmt.Println(str)

	// analysis back json
	b, err := sjson.NewJson([]byte(str))
	if err != nil {
		fmt.Println("sjson err:", err)
		return dp, err
	}
	code, err := b.Get("code").String()
	if err != nil {
		return dp, err
	}
	if code != "200" {
		fmt.Println("Read data failed")
		return dp, errors.New("data not found")
	}

	// 但前传感器值
	current_value, err := b.Get("data").Get("current_value").Float64()
	if err != nil {
		return dp, err
	}
	fmt.Println("current_value:", current_value)
	current_time, err := b.Get("data").Get("at").String()
	if err != nil {
		return dp, err
	}
	fmt.Println("current_time:", current_time)
	// test time.Parse, do not care
	t, err := time.Parse("2006-01-02T15:04:05-0700", current_time)
	if err != nil {
		fmt.Println("parse time err:", err)
	}
	fmt.Println("time:", t)

	dp.At = current_time
	dp.Value = fmt.Sprintf("%.2f", current_value)
	return dp, nil
}

// 发送一个控制命令给设备
func (this *JDPlusDevelopmentPlatform) SendControlCommand(dev *Device, cmd []ControlCommand) error {
	feed_id := this.Device.FeedId
	// 重定向用户指定的设备
	if dev != nil {
		if len(dev.FeedId) != 0 {
			feed_id = dev.FeedId
		}
	}

	// 生成一个控制命令json
	js := new(ControlCommandslice)
	js.ControlCommands = cmd
	data, err := json.Marshal(js)
	if err != nil {
		fmt.Println("json err:", err)
		return err
	}
	fmt.Println(string(data))

	// “上传数据”即可以是用户向设备发送的控制命令上传云端，也可以是设备将自己
	// 采集/状态数据上传云端。这两种模式的接口api一样。
	// 注：“请求方法”=“PUT”发送控制命令；“请求方法”=“POST”创建新数据。
	req := httplib.Put(this.RestApiUrl + "feeds/" + feed_id).SetTLSClientConfig(this.SSLconfig)
	req.Debug(true)
	req.Header(this.Header[JDUserAgent], JDPlusUserAgentDefault)
	req.Header(this.Header[JDPlusHeardKey], this.Device.Accesskey)
	req.SetProtocolVersion("HTTP/1.1")
	// 透传的控制命令
	//data = []byte(`[{"stream_id":"switch","current_value":"0","at":"2013-04-22T01:35:43+0800"}]`) // for debug
	// demo中只有一个控制命令，所以这里只发送一个stream_id，如需要发送两个以上，请修改下面这条语句
	cmdjsonstr := fmt.Sprintf("[{\"stream_id\":\"%s\",\"current_value\":\"%s\",\"at\":\"%s\"}]", cmd[0].StreamId, cmd[0].CurrentValue, cmd[0].AtTime)
	data = []byte(cmdjsonstr)
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
		fmt.Println("control device failed")
		return errors.New("control device failed")
	}

	return nil
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
