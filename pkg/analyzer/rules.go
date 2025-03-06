package analyzer

import (
	"go-xiaotianquan/pkg/logger"
	"go-xiaotianquan/pkg/models"
	"math"
	"net"
	"strings"

	//"sync"
	"time"
	//"go-xiaotianquan/pkg/storage"
	//"github.com/oschwald/geoip2-golang"
)

// calculateDistance 计算两个坐标点之间的距离（单位：公里）
// 使用Haversine公式计算两个经纬度坐标之间的球面距离（单位：公里）
func calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // 地球平均半径（公里）

	// 将角度转换为弧度
	lat1Rad := lat1 * math.Pi / 180
	lon1Rad := lon1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	lon2Rad := lon2 * math.Pi / 180

	// 计算纬度差和经度差
	dLat := lat2Rad - lat1Rad
	dLon := lon2Rad - lon1Rad

	// Haversine公式计算
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c // 最终距离
}

// 单个用户（fingerprint：ip-cookie-useragent）在5分钟内访问的数据条数超过10条时，风险分值设置为3
// checkSensitiveDataAccess 检查敏感数据访问频率
func (ra *RiskAnalyzer) checkSensitiveDataAccess(fingerprint models.UserFingerprint) float64 {
	history := ra.userAccessHistory[fingerprint]
	if len(history) == 0 {
		return 0
	}

	accessCount := 0
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	for _, data := range history {
		if data.Timestamp.Before(fiveMinutesAgo) {
			continue
		}
		accessCount++
	}

	if accessCount > 10 {
		return 3.0 // 符合需求的风险分值
	}
	return 0
}

// 单个用户（fingerprint：ip-cookie-useragent）在10分钟、60分钟、4小时窗口时间内获取的数据量超过N时，设置风险值为4
// checkDataDownloadVolumeFromHistory 检查数据下载量
func (ra *RiskAnalyzer) checkDataDownloadVolumeFromHistory(fingerprint models.UserFingerprint) float64 {
	history := ra.userAccessHistory[fingerprint]
	now := time.Now()

	var size10m, size1h, size4h int64
	for _, data := range history {
		duration := now.Sub(data.Timestamp)
		// 从 PacketData 中获取数据大小
		size := int64(len(data.HTTP.Response.Body.Content))

		if duration <= 10*time.Minute {
			size10m += size
		}
		if duration <= time.Hour {
			size1h += size
		}
		if duration <= 4*time.Hour {
			size4h += size
		}
	}

	// 根据需求设置的阈值
	if size10m > 10*1024*1024 || size1h > 50*1024*1024 || size4h > 200*1024*1024 {
		return 4.0
	}
	return 0
}

// 同一个cookie在60分钟内使用了不同的IP，风险值设置为6
// checkIPSwitchingHourly 检查IP切换（小时级）
func (ra *RiskAnalyzer) checkIPSwitchingHourly(cookie string, ip string) float64 {
	if cookie == "" || ip == "" {
		return 0
	}

	// 初始化IP历史记录
	if _, exists := ra.cookieIPHistory[cookie]; !exists {
		ra.cookieIPHistory[cookie] = make(map[string]time.Time)
	}

	// 记录当前IP
	now := time.Now()
	ra.cookieIPHistory[cookie][ip] = now

	// 检查60分钟内的IP数量
	uniqueIPs := make(map[string]bool)
	oneHourAgo := now.Add(-time.Hour)

	for historyIP, timestamp := range ra.cookieIPHistory[cookie] {
		if timestamp.After(oneHourAgo) {
			uniqueIPs[historyIP] = true
		}
	}

	if len(uniqueIPs) >= 2 {
		return 6.0 // 调整为需求要求的6分风险值
	}
	return 0
}

// checkOperationTimeEnhanced 检查操作时间（增强版）
func (ra *RiskAnalyzer) checkOperationTimeEnhanced(data models.PacketData) float64 {
	hour := data.Timestamp.Hour()
	weekday := data.Timestamp.Weekday()

	// 检查是否是敏感时间段 (22点-7点及周末)
	isNightTime := hour >= 22 || hour < 7
	isWeekend := weekday == time.Saturday || weekday == time.Sunday

	// 获取用户ID（这里使用Cookie作为用户标识）
	userID := data.HTTP.Request.Headers.Cookie
	if userID != "" && ra.isSensitiveDataAccess(data) {
		// 检查敏感数据访问是否异常
		avgAccess := ra.getSensitiveDataAvg(userID)

		// 当前访问计数（当天）
		todayCount := ra.getTodaySensitiveAccessCount(userID)

		// 工作日访问敏感数据超过平均值3倍
		if !isWeekend && avgAccess > 0 && float64(todayCount) > avgAccess*3 {
			return 6.0
		}

		// 非工作日访问敏感数据超过平均值2.5倍
		if isWeekend && avgAccess > 0 && float64(todayCount) > avgAccess*2.5 {
			return 6.0
		}
	}

	// 非工作时间风险分值
	if isNightTime {
		return 3.0
	}

	// 周末风险分值
	if isWeekend {
		return 2.0
	}

	return 0
}

// getSensitiveDataAvg 获取用户敏感数据访问平均值
// 如果缓存过期或不存在，则重新计算
func (ra *RiskAnalyzer) getSensitiveDataAvg(userID string) float64 {
	// 先检查内存缓存
	ra.sensitiveDataMu.RLock()
	avg, exists := ra.sensitiveDataAvg[userID]
	expiry, hasExpiry := ra.sensitiveDataExpiry[userID]
	ra.sensitiveDataMu.RUnlock()

	now := time.Now()

	// 如果缓存有效，直接返回
	if exists && hasExpiry && now.Before(expiry) {
		return avg
	}

	// 使用互斥锁确保同一用户ID只有一个goroutine在计算
	ra.sensitiveDataMu.Lock()

	// 双重检查，避免在获取锁期间其他goroutine已经计算过
	avg, exists = ra.sensitiveDataAvg[userID]
	expiry, hasExpiry = ra.sensitiveDataExpiry[userID]
	if exists && hasExpiry && now.Before(expiry) {
		ra.sensitiveDataMu.Unlock()
		return avg
	}

	// 尝试从数据库获取有效的缓存
	dbAvg, dbExpiry, err := ra.storage.GetSensitiveDataAvg(userID)
	if err == nil && now.Before(dbExpiry) {
		// 数据库中有有效缓存，更新内存缓存
		ra.sensitiveDataAvg[userID] = dbAvg
		ra.sensitiveDataExpiry[userID] = dbExpiry
		ra.sensitiveDataMu.Unlock()
		return dbAvg
	}

	// 缓存过期或不存在，重新计算
	avg = ra.calculateSensitiveDataAvg(userID)
	expiry = now.Add(24 * time.Hour)

	// 更新内存缓存
	ra.sensitiveDataAvg[userID] = avg
	ra.sensitiveDataExpiry[userID] = expiry
	ra.sensitiveDataMu.Unlock()

	// 异步保存到数据库
	go func(id string, value float64, exp time.Time) {
		if err := ra.storage.SaveSensitiveDataAvg(id, value, exp); err != nil {
			logger.Log.Errorf("保存敏感数据平均值失败: %v", err)
		}
	}(userID, avg, expiry)

	return avg
}

// calculateSensitiveDataAvg 计算用户敏感数据访问平均值
func (ra *RiskAnalyzer) calculateSensitiveDataAvg(userID string) float64 {
	// 获取最近30天的数据
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)

	// 从数据库加载历史数据
	history, err := ra.storage.GetUserAccessHistory(userID, thirtyDaysAgo)
	if err != nil {
		logger.Log.Errorf("获取用户访问历史失败: %v", err)
		return 0
	}

	// 按工作日统计敏感数据访问次数
	workdayAccessCount := 0
	workdayCount := 0

	// 用于去重，确保每个工作日只计算一次
	workdayMap := make(map[string]bool)

	for _, data := range history {
		// 跳过非敏感数据访问
		if !ra.isSensitiveDataAccess(data) {
			continue
		}

		// 跳过周末数据
		weekday := data.Timestamp.Weekday()
		if weekday == time.Saturday || weekday == time.Sunday {
			continue
		}

		// 按日期统计（每个工作日计算一次）
		dateStr := data.Timestamp.Format("2006-01-02")
		if !workdayMap[dateStr] {
			workdayMap[dateStr] = true
			workdayCount++
		}

		workdayAccessCount++
	}

	// 计算平均值
	if workdayCount > 0 {
		return float64(workdayAccessCount) / float64(workdayCount)
	}

	return 0
}

// getTodaySensitiveAccessCount 获取当天敏感数据访问次数
func (ra *RiskAnalyzer) getTodaySensitiveAccessCount(userID string) int {
	// 获取当天开始时间
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// 从数据库加载当天数据
	history, err := ra.storage.GetUserAccessHistory(userID, startOfDay)
	if err != nil {
		logger.Log.Errorf("获取用户当天访问历史失败: %v", err)
		return 0
	}

	// 统计敏感数据访问次数
	count := 0
	for _, data := range history {
		if ra.isSensitiveDataAccess(data) {
			count++
		}
	}

	return count
}

// saveSensitiveDataAvgToDB 将敏感数据平均值保存到数据库
func (ra *RiskAnalyzer) saveSensitiveDataAvgToDB(userID string, avg float64) {
	err := ra.storage.SaveSensitiveDataAvg(userID, avg, time.Now().Add(24*time.Hour))
	if err != nil {
		logger.Log.Errorf("保存敏感数据平均值失败: %v", err)
	}
}

// isSensitiveDataAccess 判断是否为敏感数据访问
func (ra *RiskAnalyzer) isSensitiveDataAccess(data models.PacketData) bool {
	// 敏感URL路径关键词
	sensitiveURLPaths := []string{
		"/api/user",
		"/api/admin",
		"/api/finance",
		"/api/account",
		"/api/sensitive",
		"/internal/",
	}

	// 检查URL是否包含敏感路径
	for _, path := range sensitiveURLPaths {
		if strings.Contains(data.URLFull, path) {
			return true
		}
	}

	// 检查响应大小是否超过阈值（可能是文件下载）
	// if len(data.HTTP.Response.Body.Content) > 1024*1024*10 { // 10MB
	// 	return true
	// }

	return false
}

// checkHistoricalRisksEnhanced 检查历史风险（增强版）
func (ra *RiskAnalyzer) checkHistoricalRisksEnhanced(data models.PacketData) float64 {
	// 检查IP是否有历史风险记录
	events, exists := ra.ipRiskHistory[data.ClientIP]
	if !exists || len(events) == 0 {
		return 0
	}

	// 只考虑24小时内的历史风险事件
	var score float64
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)

	recentRiskCount := 0
	for _, event := range events {
		if event.Timestamp.After(twentyFourHoursAgo) {
			score += event.RiskScore * 0.1 // 历史风险权重为0.1
			recentRiskCount++
		}
	}

	// 如果24小时内有3次以上高风险事件，增加额外风险分值
	if recentRiskCount >= 3 {
		score += 2.0
	}

	return score
}

// 同一个cookie在10分钟内使用了不同的IP，风险值设置为6
// checkHighIPSwitching 检查高频IP切换（10分钟内）
func (ra *RiskAnalyzer) checkHighIPSwitching(fingerprint models.UserFingerprint) float64 {
	if fingerprint.Cookie == "" || fingerprint.IP == "" {
		return 0
	}

	// 初始化IP历史记录
	if _, exists := ra.cookieIPHistory[fingerprint.Cookie]; !exists {
		ra.cookieIPHistory[fingerprint.Cookie] = make(map[string]time.Time)
	}

	// 记录当前IP
	now := time.Now()
	ra.cookieIPHistory[fingerprint.Cookie][fingerprint.IP] = now

	// 统计10分钟内使用的不同IP数量
	uniqueIPs := make(map[string]bool)
	tenMinutesAgo := now.Add(-10 * time.Minute)

	for ip, timestamp := range ra.cookieIPHistory[fingerprint.Cookie] {
		if timestamp.After(tenMinutesAgo) {
			uniqueIPs[ip] = true
		}
	}

	if len(uniqueIPs) > 2 {
		return 6.0 // 符合需求的风险分值
	}
	return 0
}

// checkLoginIPLocation 检查登录IP地理位置
func (ra *RiskAnalyzer) checkLoginIPLocation(data models.PacketData) float64 {
	if ra.geoIP == nil {
		return 0
	}

	ip := net.ParseIP(data.ClientIP)
	if ip == nil {
		return 0
	}

	city, err := ra.geoIP.City(ip)
	if err != nil {
		logger.Log.Errorf("GeoIP查询失败: %v", err)
		return 0
	}

	// 检查是否是高风险国家/地区
	highRiskCountries := []string{"RU", "KP", "IR"}
	for _, country := range highRiskCountries {
		if city.Country.IsoCode == country {
			return 2.0
		}
	}

	return 0
}

// checkProxyFeatures 检查代理特征
func (ra *RiskAnalyzer) checkProxyFeatures(data models.PacketData) float64 {
	// 检查X-Forwarded-For头
	if data.XForwardedFor != "" && data.XForwardedFor != data.ClientIP {
		return 1.5
	}

	// 检查是否是数据中心IP
	return ra.checkDataCenterIP(data)
}

// checkGeoLocationDiff 检查地理位置差异
func (ra *RiskAnalyzer) checkGeoLocationDifference(data models.PacketData) float64 {
	if ra.geoIP == nil || data.ClientIP == "" {
		return 0
	}

	ip := net.ParseIP(data.ClientIP)
	if ip == nil {
		return 0
	}

	currentRecord, err := ra.geoIP.City(ip)
	if err != nil {
		logger.Log.Errorf("GeoIP查询失败: %v", err)
		return 0
	}

	// 获取用户的常用IP
	fingerprint := models.UserFingerprint{
		Cookie:    data.HTTP.Request.Headers.Cookie,
		UserAgent: data.HTTP.Request.Headers.UserAgent,
	}

	history := ra.userAccessHistory[fingerprint]
	if len(history) <= 1 {
		return 0
	}

	// 统计历史IP使用频率
	ipFrequency := make(map[string]int)
	for _, histData := range history {
		if histData.ClientIP != data.ClientIP {
			ipFrequency[histData.ClientIP]++
		}
	}

	// 找出最常用的IP
	var mostUsedIP string
	var maxFreq int
	for ip, freq := range ipFrequency {
		if freq > maxFreq {
			maxFreq = freq
			mostUsedIP = ip
		}
	}

	if mostUsedIP == "" || maxFreq < 3 {
		return 0
	}

	// 计算地理距离
	mostUsedIPObj := net.ParseIP(mostUsedIP)
	if mostUsedIPObj == nil {
		return 0
	}

	mostUsedRecord, err := ra.geoIP.City(mostUsedIPObj)
	if err != nil {
		return 0
	}

	distance := calculateDistance(
		currentRecord.Location.Latitude,
		currentRecord.Location.Longitude,
		mostUsedRecord.Location.Latitude,
		mostUsedRecord.Location.Longitude,
	)

	if distance > 300 {
		return 4.0
	}
	return 0
}

// checkCrossRegionAccess 检查跨地域访问
func (ra *RiskAnalyzer) checkCrossRegionAccess(data models.PacketData) float64 {
	if ra.geoIP == nil || data.ClientIP == "" {
		return 0
	}

	ip := net.ParseIP(data.ClientIP)
	if ip == nil {
		return 0
	}

	currentRecord, err := ra.geoIP.City(ip)
	if err != nil {
		return 0
	}

	// 获取当前城市
	currentCity := ""
	if len(currentRecord.Subdivisions) > 0 {
		currentCity = currentRecord.Subdivisions[0].Names["zh-CN"]
	}

	// 检查5分钟内的访问记录
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
	cookie := data.HTTP.Request.Headers.Cookie

	for fp, history := range ra.userAccessHistory {
		if fp.Cookie == cookie {
			for _, record := range history {
				if record.Timestamp.After(fiveMinutesAgo) && record.ClientIP != data.ClientIP {
					historyIP := net.ParseIP(record.ClientIP)
					if historyIP == nil {
						continue
					}

					historyRecord, err := ra.geoIP.City(historyIP)
					if err != nil {
						continue
					}

					historyCity := ""
					if len(historyRecord.Subdivisions) > 0 {
						historyCity = historyRecord.Subdivisions[0].Names["zh-CN"]
					}
					// 如果城市不同且距离超过100公里，返回风险分值
					if currentCity != historyCity {
						distance := calculateDistance(
							currentRecord.Location.Latitude,
							currentRecord.Location.Longitude,
							historyRecord.Location.Latitude,
							historyRecord.Location.Longitude,
						)
						if distance > 100 {
							return 5.0
						}
					}
				}
			}
		}
	}
	return 0
}

// checkNonMainlandChina 检查非中国大陆IP
func (ra *RiskAnalyzer) checkNonMainlandChina(data models.PacketData) float64 {
	if ra.geoIP == nil {
		return 0
	}

	ip := net.ParseIP(data.ClientIP)
	if ip == nil {
		return 0
	}

	city, err := ra.geoIP.City(ip)
	if err != nil {
		logger.Log.Errorf("GeoIP查询失败: %v", err)
		return 0
	}

	// 如果是中国IP但不是大陆地区
	if city.Country.IsoCode == "CN" {
		// 检查是否是香港、澳门、台湾
		if len(city.Subdivisions) > 0 && (city.Subdivisions[0].IsoCode == "HK" ||
			city.Subdivisions[0].IsoCode == "MO" ||
			city.Subdivisions[0].IsoCode == "TW") {
			return 8.0
		}
		return 0
	}

	// 非中国IP
	return 8.0
}

// checkDataCenterIP 检查数据中心IP
func (ra *RiskAnalyzer) checkDataCenterIP(data models.PacketData) float64 {
	if ra.asnDB == nil {
		return 0
	}

	ip := net.ParseIP(data.ClientIP)
	if ip == nil {
		return 0
	}

	asn, err := ra.asnDB.ASN(ip)
	if err != nil {
		logger.Log.Errorf("ASN查询失败: %v", err)
		return 0
	}

	// 已知的数据中心和云服务提供商ASN
	dataCenterASNs := map[uint]bool{
		16509: true, // Amazon AWS
		14618: true, // Amazon AWS
		8075:  true, // Microsoft Azure
		45102: true, // Alibaba Cloud
		37963: true, // Alibaba Cloud
		4134:  true, // Chinanet
		4837:  true, // China Unicom
	}

	if dataCenterASNs[asn.AutonomousSystemNumber] {
		return 1.0
	}

	return 0
}
