package analyzer

import (
	"net"
	"strings"
	"sync"

	"go-xiaotianquan/pkg/config"
	"go-xiaotianquan/pkg/logger"
)

type Whitelist struct {
	nets []*net.IPNet
	mu   sync.RWMutex
}

func NewWhitelist() *Whitelist {
	w := &Whitelist{
		nets: make([]*net.IPNet, 0),
	}
	// 从配置文件初始化白名单
	w.initFromConfig()
	return w
}

func (w *Whitelist) initFromConfig() {
	whitelistIPs := config.GlobalConfig.Security.WhitelistIPs
	if len(whitelistIPs) > 0 {
		w.Update(whitelistIPs)
		logger.Log.Infof("从配置文件加载白名单IP: %v", whitelistIPs)
	} else {
		logger.Log.Warnf("配置文件中未找到白名单IP")
	}
}

func (w *Whitelist) Update(ips []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.nets = make([]*net.IPNet, 0, len(ips))

	for _, ip := range ips {
		// 处理CIDR格式
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}

		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			logger.Log.Errorf("无效的CIDR格式: %s, 错误: %v", ip, err)
			continue
		}
		w.nets = append(w.nets, ipnet)
		logger.Log.Debugf("添加白名单: %s", ipnet.String())
	}

	logger.Log.Infof("白名单更新完成，共 %d 条记录", len(w.nets))
}

func (w *Whitelist) ContainsIP(ipStr string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.nets) == 0 {
		//logger.Log.Infof("白名单为空，IP %s 不在白名单中", ipStr)
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		logger.Log.Warnf("无效的IP地址: %s", ipStr)
		return false
	}

	for _, ipnet := range w.nets {
		if ipnet.Contains(ip) {
			logger.Log.Debugf("IP %s 匹配白名单 %s", ipStr, ipnet.String())
			return true
		}
	}

	//logger.Log.Debugf("IP %s 不在白名单中", ipStr)
	return false
}
