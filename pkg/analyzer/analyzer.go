package analyzer

import (
	// "bytes"
	// "encoding/json"
	"go-xiaotianquan/pkg/alerter"
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/models"
	"go-xiaotianquan/pkg/storage"

	// "net/http"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// RiskAnalyzer 风险分析器
type RiskAnalyzer struct {
	mu                sync.RWMutex
	userAccessHistory map[models.UserFingerprint][]models.PacketData
	ipRiskHistory     map[string][]models.RiskEvent
	cookieIPHistory   map[string]map[string]time.Time
	storage           *storage.Storage
	geoIP             *geoip2.Reader
	asnDB             *geoip2.Reader

	// 新增字段
	sensitiveDataAvg    map[string]float64
	sensitiveDataExpiry map[string]time.Time
	sensitiveDataMu     sync.RWMutex

	// 新增白名单结构体
	whitelist *Whitelist

	// 新增告警处理器
	alerter *alerter.Alerter
}

// 更新初始化函数
func NewRiskAnalyzer(storage *storage.Storage, geoIP *geoip2.Reader, asnDB *geoip2.Reader, webhookURL string) *RiskAnalyzer {
	ra := &RiskAnalyzer{
		userAccessHistory: make(map[models.UserFingerprint][]models.PacketData),
		ipRiskHistory:     make(map[string][]models.RiskEvent),
		cookieIPHistory:   make(map[string]map[string]time.Time),
		storage:           storage,
		geoIP:             geoIP,
		asnDB:             asnDB,
		// 初始化新增字段
		sensitiveDataAvg:    make(map[string]float64),
		sensitiveDataExpiry: make(map[string]time.Time),

		// 初始化新白名单结构体
		whitelist: NewWhitelist(), // 会自动从配置文件加载白名单

		// 初始化告警处理器
		alerter: alerter.NewAlerter(storage, webhookURL),
	}
	return ra
}

// 新增白名单管理方法
// 添加从配置加载白名单的方法
func (ra *RiskAnalyzer) LoadWhitelistFromConfig(whitelistIPs []string) {
	if len(whitelistIPs) == 0 {
		logger.Log.Warnf("配置中的白名单IP列表为空")
		return
	}

	logger.Log.Infof("从配置加载白名单，共 %d 条记录", len(whitelistIPs))
	ra.UpdateWhitelist(whitelistIPs)
}

// 修改UpdateWhitelist方法，增加日志
func (ra *RiskAnalyzer) UpdateWhitelist(ips []string) {
	logger.Log.Infof("更新白名单，共 %d 条记录", len(ips))
	ra.whitelist.Update(ips) // 调用新结构体的更新方法
}

// ProcessPacket方法中的白名单检查
func (ra *RiskAnalyzer) ProcessPacket(data models.PacketData) {
	// 白名单检查前置
	if ra.whitelist.ContainsIP(data.ClientIP) {
		logger.Log.Debugf("IP %s 在白名单中，跳过分析", data.ClientIP)
		return
	}

	ra.mu.Lock()
	defer ra.mu.Unlock()

	// 构建用户指纹（组合IP、UserAgent、Cookie）
	fingerprint := models.UserFingerprint{
		IP:        data.ClientIP,
		UserAgent: data.HTTP.Request.Headers.UserAgent,
		Cookie:    data.HTTP.Request.Headers.Cookie,
	}

	// 更新访问历史记录
	ra.userAccessHistory[fingerprint] = append(ra.userAccessHistory[fingerprint], data)

	// 综合计算风险评分（调用rules.go中的规则检查方法）
	riskScore := ra.checkDataDownloadVolumeFromHistory(fingerprint) +
		ra.checkOperationTimeEnhanced(data) +
		ra.checkHighIPSwitching(fingerprint) + // 修改调用方式
		ra.checkLoginIPLocation(data) +
		ra.checkProxyFeatures(data) +
		ra.checkHistoricalRisksEnhanced(data) +
		ra.checkNonMainlandChina(data) +
		ra.checkDataCenterIP(data)

	logger.Log.Infof("风险分析完成: client_ip=%s, risk_score=%.2f", data.ClientIP, riskScore)

	// 记录风险事件
	event := models.RiskEvent{
		Fingerprint: fingerprint,
		RiskScore:   riskScore,
		Timestamp:   time.Now(),
		RiskType:    ra.getRiskType(riskScore),
		AlertRules:  ra.getAlertRules(data, riskScore),
	}
	ra.ipRiskHistory[data.ClientIP] = append(ra.ipRiskHistory[data.ClientIP], event)

	// 保存分析结果
	if err := ra.storage.SaveAnalysisResult(data, riskScore); err != nil {
		logger.Log.Errorf("保存分析结果失败: %v", err)
	}

	// 触发告警（分值>=8）
	if riskScore >= 8 {
		// 获取告警规则
		alertRules := ra.getAlertRules(data, riskScore)

		// 使用告警处理器触发告警
		if err := ra.alerter.TriggerAlert(data, riskScore, alertRules); err != nil {
			logger.Log.Errorf("触发告警失败: %v", err)
		}
	}

	// 清理过期数据
	ra.cleanupOldData()
}

// cleanupOldData 清理过期数据
func (ra *RiskAnalyzer) cleanupOldData() {
	now := time.Now()
	eightHoursAgo := now.Add(-1 * time.Hour)      //临时修改为1小时，原8小时
	twentyFourHoursAgo := now.Add(-1 * time.Hour) //临时修改为1小时，原24小时

	// 清理用户访问历史（8小时）
	for fp, history := range ra.userAccessHistory {
		var newHistory []models.PacketData
		for _, data := range history {
			if data.Timestamp.After(eightHoursAgo) {
				newHistory = append(newHistory, data)
			}
		}
		if len(newHistory) > 0 {
			ra.userAccessHistory[fp] = newHistory
		} else {
			delete(ra.userAccessHistory, fp)
		}
	}

	// 清理IP风险历史（24小时）
	for ip, events := range ra.ipRiskHistory {
		var newEvents []models.RiskEvent
		for _, event := range events {
			if event.Timestamp.After(twentyFourHoursAgo) {
				newEvents = append(newEvents, event)
			}
		}
		if len(newEvents) > 0 {
			ra.ipRiskHistory[ip] = newEvents
		} else {
			delete(ra.ipRiskHistory, ip)
		}
	}
}

// getRiskType 获取风险类型
func (ra *RiskAnalyzer) getRiskType(score float64) string {
	if score >= 8 {
		return "高风险"
	} else if score >= 5 {
		return "中风险"
	}
	return "低风险"
}

// getAlertRules 获取告警规则
func (ra *RiskAnalyzer) getAlertRules(data models.PacketData, riskScore float64) []string {
	var rules []string
	fingerprint := models.UserFingerprint{
		IP:        data.ClientIP,
		UserAgent: data.HTTP.Request.Headers.UserAgent,
		Cookie:    data.HTTP.Request.Headers.Cookie,
	}

	if ra.checkDataDownloadVolumeFromHistory(fingerprint) > 0 {
		rules = append(rules, "数据下载量异常")
	}
	if ra.checkOperationTimeEnhanced(data) > 0 {
		rules = append(rules, "非常规操作时间")
	}
	if ra.checkHighIPSwitching(fingerprint) > 0 {
		rules = append(rules, "IP高频切换")
	}
	if ra.checkLoginIPLocation(data) > 0 {
		rules = append(rules, "地理位置异常")
	}
	if ra.checkProxyFeatures(data) > 0 {
		rules = append(rules, "代理IP访问")
	}
	if ra.checkHistoricalRisksEnhanced(data) > 0 {
		rules = append(rules, "历史高风险")
	}
	if ra.checkNonMainlandChina(data) > 0 {
		rules = append(rules, "非中国大陆IP")
	}
	if ra.checkDataCenterIP(data) > 0 {
		rules = append(rules, "数据中心IP")
	}

	return rules
}
