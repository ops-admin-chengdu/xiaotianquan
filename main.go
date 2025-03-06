package main

import (
	// "net/http"  // Add this
	"go-xiaotianquan/pkg/analyzer"
	"go-xiaotianquan/pkg/config"
	"go-xiaotianquan/pkg/consumer"
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/storage"
	"os"
	"os/signal"
	"syscall"

	// "go-xiaotianquan/pkg/metrics"  // Remove this
	"github.com/oschwald/geoip2-golang"
	//"github.com/prometheus/client_golang/prometheus/promhttp"
)

func init() {
	// 初始化配置
	if err := config.Init(); err != nil {
		logger.Log.Fatal("初始化配置失败:", err)
	}

	// 初始化日志
	if err := logger.Init(); err != nil {
		logger.Log.Fatal("初始化日志失败:", err)
	}

	// 启动指标服务
	// go func() {
	//     http.Handle("/metrics", promhttp.Handler())
	//     if err := http.ListenAndServe(":2112", nil); err != nil {
	//         logger.Log.Error("指标服务启动失败:", err)
	//     }
	// }()

}

func main() {
	cfg := config.GlobalConfig

	logger.Log.Info("开始启动风险分析服务...")
	logger.Log.Infof("Kafka配置: brokers=%v, topic=%s", cfg.Kafka.Brokers, cfg.Kafka.Topic)

	// 初始化存储层 (InfluxDB 和 MySQL)
	storage, err := storage.NewStorage(&cfg)
	if err != nil {
		logger.Log.Fatal("初始化存储层失败:", err)
	}
	defer storage.Close()
	logger.Log.Info("存储层初始化成功")

	// 初始化GeoIP数据库
	geoIP, err := geoip2.Open(cfg.GeoIP.CityPath)
	if err != nil {
		logger.Log.Fatal("初始化GeoIP数据库失败:", err)
	}
	defer geoIP.Close()

	// 初始化ASN数据库
	asnDB, err := geoip2.Open(cfg.GeoIP.ASNPath)
	if err != nil {
		logger.Log.Fatal("初始化ASN数据库失败:", err)
	}
	defer asnDB.Close()

	// 初始化风险分析器
	riskAnalyzer := analyzer.NewRiskAnalyzer(
		storage,
		geoIP,
		asnDB,
		cfg.Webhook.URL,
	)

	// 初始化Kafka消费者
	consumer, err := consumer.NewConsumer(
		cfg.Kafka.Brokers,
		riskAnalyzer,
	)
	if err != nil {
		logger.Log.Fatal("初始化Kafka消费者失败:", err)
	}
	defer consumer.Close()
	logger.Log.Info("Kafka消费者初始化成功")

	// 优雅退出处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动消费
	logger.Log.Info("正在启动Kafka消费...")
	go func() {
		logger.Log.Infof("开始消费topic: %s", cfg.Kafka.Topic)
		if err := consumer.Start(cfg.Kafka.Topic); err != nil {
			logger.Log.Errorf("Kafka消费启动失败: %v", err)
			sigChan <- syscall.SIGTERM
			return
		}
	}()

	logger.Log.Info("服务启动完成，等待消息...")

	// 等待退出信号
	sig := <-sigChan
	logger.Log.Infof("接收到信号 %v, 开始优雅退出", sig)
}
