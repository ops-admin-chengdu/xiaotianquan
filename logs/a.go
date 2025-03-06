package main

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/confluentinc/confluent-kafka-go/kafka"
)

// 定义一个结构体来表示消息的数据结构
type Message struct {
    Timestamp string        `json:"@timestamp"`
    Metadata  Metadata      `json:"@metadata"`
    Type      string        `json:"type"`
    Method    string        `json:"method"`
    URL       URL           `json:"url"`
    Server    Server        `json:"server"`
    Client    Client        `json:"related"`
    HTTP      HTTPResponse  `json:"http"`
    cookie    string        `json:"cookie"`
    UserAgent string        `json:"useragent"`
}

type Metadata struct {
    Beat    string `json:"beat"`
    Type    string `json:"type"`
    Version string `json:"version"`
}

type URL struct {
    Full string `json:"full"`
}

type Server struct {
    IP string `json:"ip"`
}

type Client struct {
    IP []string `json:"ip"`
}


type HTTPResponse struct {
	Response struct {
		Body struct {
			Content string `json:"content"`
		} `json:"body"`
		StatusCode int `json:"status_code"`
		Request    struct {
			Headers struct {
				Cookie    string `json:"cookie"`     // Cookie 字段
				UserAgent string `json:"useragent"` // UserAgent 字段
			} `json:"headers"`
		} `json:"request"`
	} `json:"response"`
}

//type HTTPResponse struct {
//    Response struct {
//        Body struct {
//            Content string `json:"content"`
//        } `json:"body"`
//        StatusCode int `json:"status_code"`
//    } `json:"response"`
//}
//}
func main() {
    // 配置Kafka消费者
    consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
        "bootstrap.servers": "xiaotianquan-kafka", // 替换为你的Kafka broker地址
        "group.id":          "tmp",    // 替换为你的消费者组ID
        "auto.offset.reset": "earliest",
    })
    if err != nil {
        fmt.Printf("Failed to create consumer: %s\n", err)
        return
    }

    defer consumer.Close()

    // 订阅主题
    topics := []string{"beats"} // 替换为你的Kafka主题名称
    err = consumer.SubscribeTopics(topics, nil)
    if err != nil {
        fmt.Printf("Failed to subscribe to topic: %s\n", err)
        return
    }

    fmt.Println("Consuming messages...")

    for {
        msg, err := consumer.ReadMessage(10 * time.Second) // 使用超时时间
        if err != nil {
            fmt.Printf("Consumer error: %v\n", err)
            continue
        }

        // 解析JSON数据
        var message Message
        if err := json.Unmarshal(msg.Value, &message); err != nil {
            fmt.Printf("Failed to parse JSON message: %v\n", err)
            continue
        }

        // 打印解析后的消息
        fmt.Printf("Received message:\n")
        fmt.Printf("Timestamp: %s\n", message.Timestamp)
        fmt.Printf("Metadata: %+v\n", message.Metadata)
        fmt.Printf("Type: %s\n", message.Type)
        fmt.Printf("Method: %s\n", message.Method)
        fmt.Printf("URL: %+v\n", message.URL)
        fmt.Printf("Server: %+v\n", message.Server)
        fmt.Printf("Client: %+v\n", message.Client)
        fmt.Printf("HTTP Response: %+v\n", message.HTTP.Response)
    }
}
