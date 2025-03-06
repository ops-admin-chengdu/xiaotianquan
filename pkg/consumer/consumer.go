package consumer

import (
	"context"
	"encoding/json"
	"go-xiaotianquan/pkg/analyzer"
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/models"
	"time"

	"github.com/IBM/sarama"
)

type Consumer struct {
	consumer sarama.ConsumerGroup
	analyzer *analyzer.RiskAnalyzer
	ready    chan bool
}

func NewConsumer(brokers []string, analyzer *analyzer.RiskAnalyzer) (*Consumer, error) {
	config := sarama.NewConfig()
	version, err := sarama.ParseKafkaVersion("2.1.0")
	if err != nil {
		return nil, err
	}
	config.Version = version
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetOldest // 修改为从最早的消息开始消费
	config.Consumer.Return.Errors = true
	config.Consumer.Group.Session.Timeout = 20 * time.Second
	config.Consumer.Group.Heartbeat.Interval = 6 * time.Second
	config.Net.DialTimeout = 30 * time.Second
	config.Net.ReadTimeout = 30 * time.Second
	config.Net.WriteTimeout = 30 * time.Second

	logger.Log.Infof("正在连接 Kafka brokers: %v", brokers)
	group, err := sarama.NewConsumerGroup(brokers, "risk-analyzer", config)
	if err != nil {
		return nil, err
	}

	return &Consumer{
		consumer: group,
		analyzer: analyzer,
		ready:    make(chan bool),
	}, nil
}

func (c *Consumer) Start(topic string) error {
	topics := []string{topic}
	ctx := context.Background()

	logger.Log.Infof("开始消费 topic: %s", topic)
	for {
		// 消费循环
		if err := c.consumer.Consume(ctx, topics, c); err != nil {
			logger.Log.Errorf("消费出错: %v", err)
			time.Sleep(time.Second * 5)
			continue
		}

		// 检查上下文是否被取消
		if ctx.Err() != nil {
			logger.Log.Errorf("上下文被取消: %v", ctx.Err())
			return ctx.Err()
		}

		// 重置 ready 通道
		c.ready = make(chan bool)
	}
}

// Required methods for sarama.ConsumerGroupHandler interface
func (c *Consumer) Setup(_ sarama.ConsumerGroupSession) error {
	close(c.ready)
	return nil
}

func (c *Consumer) Cleanup(_ sarama.ConsumerGroupSession) error {
	return nil
}

func (c *Consumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case message := <-claim.Messages():
			logger.Log.Infof("收到消息: topic=%s, partition=%d, offset=%d",
				message.Topic, message.Partition, message.Offset)

			var packetData models.PacketData
			if err := json.Unmarshal(message.Value, &packetData); err != nil {
				logger.Log.Errorf("解析消息失败: %v, raw message: %s", err, string(message.Value))
				session.MarkMessage(message, "")
				continue
			}

			// 填充兼容性字段
			if packetData.ClientIP == "" {
				// 从 Related.IP 列表中取最后一个值作为客户端 IP
				if len(packetData.Related.IP) > 0 {
					packetData.ClientIP = packetData.Related.IP[len(packetData.Related.IP)-1]
				}
			}

			if packetData.URLFull == "" {
				packetData.URLFull = packetData.URL.Full
			}

			if packetData.Cookie == "" {
				packetData.Cookie = packetData.HTTP.Request.Headers.Cookie
			}

			if packetData.UserAgent == "" {
				packetData.UserAgent = packetData.HTTP.Request.Headers.UserAgent
			}

			if packetData.ResponseContent.Raw == "" {
				packetData.ResponseContent.Raw = packetData.HTTP.Response.Body.Content
			}

			// 数据完整性检查
			if packetData.ClientIP == "" || packetData.URLFull == "" {
				logger.Log.Warnf("数据不完整: client_ip=%s, url=%s, raw message: %s",
					packetData.ClientIP, packetData.URLFull, string(message.Value))
				session.MarkMessage(message, "")
				continue
			}

			//logger.Log.Infof("处理数据包: client_ip=%s, url=%s",
			//	packetData.ClientIP, packetData.URLFull)
			// logger.Log.Warnf("原始数据: client_ip=%s, url=%s, raw message: %s",
			// 	packetData.ClientIP, packetData.URLFull, string(message.Value))

			c.analyzer.ProcessPacket(packetData)
			session.MarkMessage(message, "")

		case <-session.Context().Done():
			return nil
		}
	}
}

func (c *Consumer) Close() error {
	return c.consumer.Close()
}
