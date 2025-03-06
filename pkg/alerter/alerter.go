package alerter

import (
	"bytes"
	"encoding/json"
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/models"
	"go-xiaotianquan/pkg/storage"
	"net/http"
	"sync"
	"time"
)

// Alerter 告警处理器
type Alerter struct {
	storage           *storage.Storage
	webhookURL        string
	alertHistory      map[string]time.Time // 用户指纹 -> 最后告警时间
	alertHistoryMu    sync.RWMutex
	alertCooldownTime time.Duration // 告警冷却时间
}

// NewAlerter 创建告警处理器
func NewAlerter(storage *storage.Storage, webhookURL string) *Alerter {
	a := &Alerter{
		storage:           storage,
		webhookURL:        webhookURL,
		alertHistory:      make(map[string]time.Time),
		alertCooldownTime: 10 * time.Hour, // 告警冻结时长为1小时
	}

	// 从数据库加载最近一小时的告警记录
	if err := a.loadRecentAlerts(); err != nil {
		logger.Log.Errorf("加载最近告警记录失败: %v", err)
	}

	// 启动定时清理任务
	go func() {
		ticker := time.NewTicker(1 * time.Minute) // 每分钟清理一次
		defer ticker.Stop()

		for range ticker.C {
			a.CleanupOldHistory()
			logger.Log.Debugf("已完成告警历史清理，当前记录数: %d", len(a.alertHistory))
		}
	}()

	return a
}

// loadRecentAlerts 从数据库加载最近一小时的告警记录
func (a *Alerter) loadRecentAlerts() error {
	// 查询最近一小时的告警记录
	query := `
		SELECT client_ip, cookie, created_at 
		FROM alert_events 
		WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
	`

	rows, err := a.storage.GetDB().Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	a.alertHistoryMu.Lock()
	defer a.alertHistoryMu.Unlock()

	// 遍历结果并添加到内存中
	for rows.Next() {
		var clientIP, cookie string
		var createdAt time.Time

		if err := rows.Scan(&clientIP, &cookie, &createdAt); err != nil {
			logger.Log.Errorf("扫描告警记录失败: %v", err)
			continue
		}

		// 构建用户指纹并记录最后告警时间
		fingerprint := cookie + ":" + clientIP
		a.alertHistory[fingerprint] = createdAt
	}

	logger.Log.Infof("已加载 %d 条最近告警记录", len(a.alertHistory))
	return nil
}

// generateUserFingerprint 生成用户指纹 (cookie+ip)
func generateUserFingerprint(data models.PacketData) string {
	return data.HTTP.Request.Headers.Cookie + ":" + data.ClientIP
}

// TriggerAlert 触发告警
func (a *Alerter) TriggerAlert(data models.PacketData, riskScore float64, alertRules []string) error {
	// 生成用户指纹
	fingerprint := generateUserFingerprint(data)

	// 检查是否在冷却期内
	a.alertHistoryMu.RLock()
	lastAlertTime, exists := a.alertHistory[fingerprint]
	a.alertHistoryMu.RUnlock()

	now := time.Now()
	if exists && now.Sub(lastAlertTime) < a.alertCooldownTime {
		logger.Log.Infof("用户 %s 在冷却期内，跳过告警", fingerprint)
		return nil
	}

	// 保存告警记录到数据库
	if err := a.storage.SaveAlertEvent(data, riskScore, alertRules); err != nil {
		logger.Log.Errorf("保存告警记录失败: %v", err)
		return err
	}

	// 发送告警通知
	if err := a.sendAlertNotification(data, riskScore, alertRules); err != nil {
		logger.Log.Errorf("发送告警通知失败: %v", err)
		return err
	}

	// 更新告警历史
	a.alertHistoryMu.Lock()
	a.alertHistory[fingerprint] = now
	a.alertHistoryMu.Unlock()

	logger.Log.Infof("成功触发告警: 用户=%s, 风险分数=%.2f", fingerprint, riskScore)
	return nil
}

// sendAlertNotification 发送告警通知
func (a *Alerter) sendAlertNotification(data models.PacketData, riskScore float64, alertRules []string) error {
	alert := struct {
		Timestamp    time.Time `json:"timestamp"`
		ClientIP     string    `json:"client_ip"`
		UserAgent    string    `json:"user_agent"`
		Cookie       string    `json:"cookie"`
		RiskScore    float64   `json:"risk_score"`
		AccessedURL  string    `json:"accessed_url"`
		AlertRules   []string  `json:"alert_rules"`
		ResponseSize int       `json:"response_size"`
	}{
		Timestamp:    time.Now(),
		ClientIP:     data.ClientIP,
		UserAgent:    data.HTTP.Request.Headers.UserAgent,
		Cookie:       data.HTTP.Request.Headers.Cookie,
		RiskScore:    riskScore,
		AccessedURL:  data.URLFull,
		AlertRules:   alertRules,
		ResponseSize: len(data.HTTP.Response.Body.Content),
	}

	jsonData, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	resp, err := http.Post(a.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// CleanupOldHistory 清理过期的告警历史
func (a *Alerter) CleanupOldHistory() {
	a.alertHistoryMu.Lock()
	defer a.alertHistoryMu.Unlock()

	now := time.Now()
	for fingerprint, lastAlertTime := range a.alertHistory {
		if now.Sub(lastAlertTime) > a.alertCooldownTime {
			delete(a.alertHistory, fingerprint)
		}
	}
}
