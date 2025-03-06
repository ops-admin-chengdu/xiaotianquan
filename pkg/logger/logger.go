package logger

import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "gopkg.in/natefinch/lumberjack.v2"
    "go-xiaotianquan/pkg/config"
)

var Log *zap.SugaredLogger

func Init() error {
    writeSyncer := zapcore.AddSync(&lumberjack.Logger{
        Filename:   config.GlobalConfig.Log.Path,
        MaxSize:    100,
        MaxBackups: 3,
        MaxAge:     7,
        Compress:   true,
    })
    
    encoderConfig := zap.NewProductionEncoderConfig()
    encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
    
    core := zapcore.NewCore(
        zapcore.NewJSONEncoder(encoderConfig),
        writeSyncer,
        zap.NewAtomicLevelAt(getLogLevel(config.GlobalConfig.Log.Level)),
    )
    
    logger := zap.New(core, zap.AddCaller())
    Log = logger.Sugar()
    return nil
}

func getLogLevel(level string) zapcore.Level {
    switch level {
    case "debug":
        return zapcore.DebugLevel
    case "info":
        return zapcore.InfoLevel
    case "warn":
        return zapcore.WarnLevel
    case "error":
        return zapcore.ErrorLevel
    default:
        return zapcore.InfoLevel
    }
}