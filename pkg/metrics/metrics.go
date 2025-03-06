package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    PacketsProcessed = promauto.NewCounter(prometheus.CounterOpts{
        Name: "xiaotianquan_packets_processed_total",
        Help: "已处理的数据包总数",
    })
    
    RiskScoreHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
        Name:    "xiaotianquan_risk_scores",
        Help:    "风险分数分布",
        Buckets: prometheus.LinearBuckets(0, 1, 10),
    })
    
    AlertsTriggered = promauto.NewCounter(prometheus.CounterOpts{
        Name: "xiaotianquan_alerts_triggered_total",
        Help: "触发的告警总数",
    })
    
    RuleExecutionTime = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "xiaotianquan_rule_execution_seconds",
            Help:    "规则执行时间",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"rule_name"},
    )
)