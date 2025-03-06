package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	InfluxDB struct {
		URL    string
		Token  string
		Org    string
		Bucket string
	}
	MySQL struct {
		DSN     string
		MaxIdle int
		MaxOpen int
	}
	Kafka struct {
		Brokers []string
		Topic   string
		GroupID string
	}
	GeoIP struct {
		CityPath string
		ASNPath  string
	}
	Webhook struct {
		URL string
	}
	Log struct {
		Level string
		Path  string
	}
	Security struct {
		WhitelistIPs []string `mapstructure:"whitelist_ips"`
	} `mapstructure:"Security"`
}

var GlobalConfig Config

func Init() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config")

	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	return viper.Unmarshal(&GlobalConfig)
}
