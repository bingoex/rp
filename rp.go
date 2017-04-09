package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
)

var proxyAddr *string = flag.String("p", "127.0.0.1:8080", "proxy addr")
var listenAddr *string = flag.String("l", ":80", "listen addr")
var fileName *string = flag.String("f", "iptables.txt", "-f connip.txt")

var (
	remote      *url.URL
	remoteProxy *httputil.ReverseProxy

	openLog  int64 //日志开关
	iptables []string
)

func usage() {
	fmt.Println("========================================================================")
	fmt.Printf("\tyou can change proxy like this %s -p www.baidu.com:80\n", os.Args[0])
	fmt.Printf("\ttry %s -h for more help\n", os.Args[0])
	fmt.Println("========================================================================")
	fmt.Printf("\n")
}

func Logf(format string, v ...interface{}) {
	if atomic.LoadInt64(&openLog) > 0 {
		log.Printf(format, v...)
	}
}

func Logln(v ...interface{}) {
	if atomic.LoadInt64(&openLog) > 0 {
		log.Println(v...)
	}
}

/* 初始化 */
func init() {
	flag.Int64Var(&openLog, "log", 1, "force open log")
	flag.Parse()
	usage()

	var err error
	proxyURL := "http://" + *proxyAddr
	if remote, err = url.Parse(proxyURL); err != nil {
		log.Fatal(err)
	}

	/* 后端代理 */
	remoteProxy = httputil.NewSingleHostReverseProxy(remote)

	fmt.Printf("proxying %s, listenning on %s\n\n", *proxyAddr, *listenAddr)
}

/* 重定向 */
func jumpTo(url string, w http.ResponseWriter) {
	Logln("url:", url)
	fmt.Fprintf(w, "<html><head><meta http-equiv=\"Refresh\" content=\"0;URL=%s\"></head><body></body></html>", url)
}

func makeOALoginURL(target string) string {
	return "http://pass.com/signin.ashx?" +
		"url=" + target
}

func dumpticket(ticket string) {
	if f, err := os.Create("ticket.txt"); err == nil {
		f.Write([]byte(ticket))
		f.Close()
	}
}

func getUserNameOA(ticket, ip string) (string, error) {
	/* 调用服务器本地程序校验签名(票据) */
	c := exec.Command("/data/CheckOaKey", ticket, ip)
	d, err := c.CombinedOutput()

	if err != nil {
		Logln("check ticket failed:", err)
		return "", errors.New("check ticket failed")
	}

	return string(d), nil
}

/* check if user in previleged list */
func verifyUser(r *http.Request) (username string, errRet error) {
	if r.Form.Get("ticket") == "" {
		Logln("no ticket param")
		return "", errors.New("no ticket param")
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	return getUserNameOA(r.Form.Get("ticket"), clientIP)
}

func CheckUserPrevilige(user string) bool {
	return true
}

func CheckIpAndUrl(path string, url string) bool {
	if path == "" || url == "" {
		return false
	}

	if isOk, _ := regexp.MatchString(".*(Some_url_not_need_to_check|other_Url).*", path); isOk {
		Logln("pass url!! ", path, url)

		for i := 0; i < len(iptables); i++ {
			if isOk, _ = regexp.MatchString(iptables[i], url); isOk {
				Logln("pass ip!!")
				return true
			}
		}
	}

	return false
}

/* 获取白名单IP */
func getIpTableLists() (iplist []string, err error) {

	file, err := os.Open(*fileName)
	defer file.Close()
	if err != nil {
		fmt.Println("Open file error")
		return nil, errors.New("Open file error")
	}

	bfRd := bufio.NewReader(file)

	for {
		line, err := bfRd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}

			fmt.Println("ReaderBytes error")
			break
		}

		Logln("iplist:", line)
		iplist = append(iplist, line[:len(line)-1])
	}

	return iplist, nil
}

func showNoPrevilige(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "You do not have previlige, contacts administrator", 400)
}

/* 服务器类 */
type Proxy struct {
	host string
}

/* http请求处理回调 */
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	orgURL := "http://" + *listenAddr + r.URL.Path
	Logf("reqhost='%s', url='%s', orgURL='%s'\n", r.URL.Host, r.URL, orgURL)

	var (
		lp  *http.Cookie
		err error
	)

	/* 白名单校验 */
	if CheckIpAndUrl(r.URL.Path, strings.Split(r.RemoteAddr, ":")[0]) {
		Logln("checkUrlPrevilige ok  pass!!")
		remoteProxy.ServeHTTP(w, r)
		return
	}

	/*  TODO 此逻辑根据用户需要修改 */
	if lp, err = r.Cookie("loginParam"); err != nil || lp.Value == "" {
		/* 没有登录，去登录服务器校验 */
		if r.Form.Get("ticket") == "" {
			jumpTo(makeOALoginURL(orgURL), w)
			return
		}

		/* 来到这里,证明刚从登录服务器验证后跳转过来的 */
		if _, err := verifyUser(r); err != nil {
			http.Error(w, "TOF's ticket is invalidate, try refresh again", 400)
			return
		}

		/* set cookie and jump with cookie again */
		w.Header().Set("Set-Cookie", fmt.Sprintf("loginParam=%s;path=/;", r.Form.Get("ticket")))
		jumpTo(orgURL, w)

		return
	} else {
		/* 来到这里，证明已经登录过，而且有了cookie里有签名（票据）*/
		var (
			user string
			err  error
		)

		clientIP := strings.Split(r.RemoteAddr, ":")[0]

		if user, err = getUserNameOA(lp.Value, clientIP); err != nil {
			jumpTo(makeOALoginURL(orgURL), w)
			return
		} else if user == "" {
			//BUG
			Logln("user is empty")
			jumpTo(makeOALoginURL(orgURL), w)
			return
		}

		/* 校验用户权限,目前什么都没做 */
		if !CheckUserPrevilige(user) {
			showNoPrevilige(w, r)
			return
		}
	}

	/* 调用系统的代理服务器类,透出请求 */
	remoteProxy.ServeHTTP(w, r)
}

func main() {
	/* 获取白名单IP */
	var err error
	iptables, err = getIpTableLists()
	if err != nil {
		Logln("getIpTableLists false error : ", err)
	}

	/* 启动proxy */
	p := &Proxy{host: *proxyAddr}
	log.Fatal(http.ListenAndServe(*listenAddr, p))
}
