-- 风险分析结果表
CREATE TABLE risk_analysis_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_ip VARCHAR(39) NOT NULL,
    cookie VARCHAR(1024),
    user_agent TEXT,
    url TEXT,
    risk_score FLOAT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    INDEX idx_client_ip (client_ip),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 告警事件表
CREATE TABLE alert_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_ip VARCHAR(39) NOT NULL,
    cookie VARCHAR(1024),
    user_agent TEXT,
    risk_score FLOAT NOT NULL,
    rules JSON NOT NULL,
    created_at TIMESTAMP NOT NULL,
    access_time TIMESTAMP NOT NULL,
    INDEX idx_client_ip (client_ip),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
