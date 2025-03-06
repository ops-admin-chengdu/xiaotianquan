package models

import (
	"time"
)

// PacketData 表示从Kafka接收的数据包结构
type PacketData struct {
	Timestamp time.Time `json:"@timestamp"`
	Metadata  struct {
		Beat    string `json:"beat"`
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"@metadata"`
	Type   string `json:"type"`
	Method string `json:"method"`
	URL    struct {
		Full string `json:"full"`
	} `json:"url"`
	Server struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"server"`
	Related struct {
		IP []string `json:"ip"`
	} `json:"related"`
	HTTP struct {
		Response struct {
			Body struct {
				Content string `json:"content"`
			} `json:"body"`
			StatusCode int `json:"status_code"`
		} `json:"response"`
		Request struct {
			Headers struct {
				Cookie    string `json:"cookie"`
				UserAgent string `json:"user_agent"`
			} `json:"headers"`
		} `json:"request"`
	} `json:"http"`

	// 兼容性字段保持不变
	ClientIP        string `json:"-"`
	URLFull         string `json:"-"`
	UserAgent       string `json:"-"`
	Cookie          string `json:"-"`
	XForwardedFor   string `json:"-"`
	ResponseContent struct {
		Raw string `json:"-"`
	} `json:"-"`
}

// UserFingerprint 用户指纹结构
type UserFingerprint struct {
	IP        string
	UserAgent string
	Cookie    string
}

// RiskEvent 风险事件结构
type RiskEvent struct {
	Fingerprint UserFingerprint
	RiskScore   float64
	Timestamp   time.Time
	RiskType    string
	AlertRules  []string
}
