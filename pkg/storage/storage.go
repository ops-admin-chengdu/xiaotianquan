package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"go-xiaotianquan/pkg/config"
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/models"

	"time"

	_ "github.com/go-sql-driver/mysql"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
)

type Storage struct {
	influxClient influxdb2.Client
	writeAPI     api.WriteAPIBlocking
	queryAPI     api.QueryAPI
	mysqlDB      *sql.DB
	org          string
	bucket       string
}

func NewStorage(cfg *config.Config) (*Storage, error) {
	// Initialize InfluxDB client
	influxClient := influxdb2.NewClient(cfg.InfluxDB.URL, cfg.InfluxDB.Token)
	writeAPI := influxClient.WriteAPIBlocking(cfg.InfluxDB.Org, cfg.InfluxDB.Bucket)
	queryAPI := influxClient.QueryAPI(cfg.InfluxDB.Org)

	// Initialize MySQL connection
	mysqlDB, err := sql.Open("mysql", cfg.MySQL.DSN)
	if err != nil {
		return nil, err
	}

	mysqlDB.SetMaxIdleConns(cfg.MySQL.MaxIdle)
	mysqlDB.SetMaxOpenConns(cfg.MySQL.MaxOpen)

	return &Storage{
		influxClient: influxClient,
		writeAPI:     writeAPI,
		queryAPI:     queryAPI,
		mysqlDB:      mysqlDB,
		org:          cfg.InfluxDB.Org,
		bucket:       cfg.InfluxDB.Bucket,
	}, nil
}

// SaveRawPacketData 保存原始数据到 InfluxDB
func (s *Storage) SaveRawPacketData(data models.PacketData) error {
	// logger.Log.Infof("保存原始数据: client_ip=%s, url=%s", data.ClientIP, data.URLFull)

	p := influxdb2.NewPoint(
		"packet_data",
		map[string]string{
			"client_ip": data.ClientIP,
			"method":    data.Method,
		},
		map[string]interface{}{
			"url":           data.URLFull,
			"response_size": len(data.HTTP.Response.Body.Content),
			"status_code":   data.HTTP.Response.StatusCode,
		},
		data.Timestamp,
	)

	if err := s.writeAPI.WritePoint(context.Background(), p); err != nil {
		logger.Log.Errorf("保存原始数据失败: %v", err)
		return err
	}

	return nil
}

// SaveAnalysisResult 保存分析结果到 MySQL
func (s *Storage) SaveAnalysisResult(data models.PacketData, riskScore float64) error {
	// logger.Log.Debugf("准备保存分析结果，cookie=%s", data.HTTP.Request.Headers.Cookie)
	query := `
        INSERT INTO risk_analysis_results (
            client_ip, cookie, user_agent, url,
            risk_score, created_at, access_time
        ) VALUES (?, ?, ?, ?, ?, NOW(),?)
    `

	_, err := s.mysqlDB.Exec(query,
		data.ClientIP,
		data.HTTP.Request.Headers.Cookie,
		data.HTTP.Request.Headers.UserAgent,
		data.URLFull,
		riskScore,
		data.Timestamp,
	)
	if err != nil {
		logger.Log.Errorf("保存分析结果失败: client_ip=%s, error=%v", data.ClientIP, err)
		return err
	}

	logger.Log.Infof("成功保存分析结果: client_ip=%s", data.ClientIP)
	return nil
}

// SaveAlertEvent 保存告警事件到 MySQL
func (s *Storage) SaveAlertEvent(data models.PacketData, riskScore float64, rules []string) error {
	query := `
        INSERT INTO alert_events (
            client_ip, cookie, user_agent,
            risk_score, rules, created_at
        ) VALUES (?, ?, ?, ?, ?, NOW())
    `

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		logger.Log.Errorf("规则序列化失败: %v", err)
		return err
	}

	result, err := s.mysqlDB.Exec(query,
		data.ClientIP,
		data.HTTP.Request.Headers.Cookie,
		data.HTTP.Request.Headers.UserAgent,
		riskScore,
		rulesJSON,
	)
	if err != nil {
		logger.Log.Errorf("保存告警事件失败: %v", err)
		return err
	}

	affected, _ := result.RowsAffected()
	logger.Log.Infof("成功保存告警事件，影响行数: %d", affected)
	return nil
}

func (s *Storage) Close() {
	s.influxClient.Close()
	s.mysqlDB.Close()
}

// QueryAPI 返回InfluxDB查询API
func (s *Storage) QueryAPI() api.QueryAPI {
	return s.queryAPI
}

// SensitiveDataAvgInfo 敏感数据平均值信息
type SensitiveDataAvgInfo struct {
	Avg    float64
	Expiry time.Time
}

// SaveSensitiveDataAvg 保存敏感数据平均值
func (s *Storage) SaveSensitiveDataAvg(userID string, avg float64, expiry time.Time) error {
	// 实现数据库存储逻辑
	// ...
	return nil
}

// GetAllSensitiveDataAvg 获取所有敏感数据平均值
func (s *Storage) GetAllSensitiveDataAvg() (map[string]SensitiveDataAvgInfo, error) {
	// 实现数据库查询逻辑
	// ...
	return nil, nil
}

// GetUserAccessHistory 获取用户访问历史
func (s *Storage) GetUserAccessHistory(userID string, startTime time.Time) ([]models.PacketData, error) {
	// 实现数据库查询逻辑
	// ...
	return nil, nil
}

// GetSensitiveDataAvg 获取用户敏感数据访问平均值
func (s *Storage) GetSensitiveDataAvg(userID string) (float64, time.Time, error) {
	query := `
        SELECT avg_value, expiry 
        FROM sensitive_data_avg 
        WHERE user_id = ? 
        AND expiry > NOW()
        ORDER BY expiry DESC 
        LIMIT 1
    `

	var avg float64
	var expiry time.Time
	err := s.mysqlDB.QueryRow(query, userID).Scan(&avg, &expiry)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, time.Time{}, nil
		}
		return 0, time.Time{}, err
	}
	return avg, expiry, nil
}

// GetDB 返回MySQL数据库连接
func (s *Storage) GetDB() *sql.DB {
	return s.mysqlDB
}
