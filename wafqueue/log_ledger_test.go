package wafqueue

// 批次确认台账的恢复语义测试（本地 SQLite，无需 crossdb 标签）。
// 钉死的行为：
//   - 三层按接收时档位全部确认才释放；部分成功只补缺失层，已完成行不复制；
//   - 未确认批次受控退避重试、到期才重试；超过上限转死信并保留原文；
//   - 副作用（IP 失败/流量统计/分析/Kafka/文件）在重放与「换管理器模拟重启」时只发生一次；
//   - 决策冻结：重试不重新采样、SkipPayloadStore 经 JSON 往返后仍不补报文；
//   - off 档无层可写时副作用照发、批次照样确认。

import (
	"SamWaf/cache"
	"SamWaf/common/queue"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	zlog.InitZLog(false, "console")
}

func openTestGorm(t *testing.T, name string) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	db, err := gorm.Open(sqlitedriver.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开测试库 %s 失败: %v", name, err)
	}
	t.Cleanup(func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func ledgerTestLog(uid, ip, action, rule string) *innerbean.WebLog {
	return &innerbean.WebLog{
		REQ_UUID: uid, HOST_CODE: "h1", USER_CODE: "u", TenantId: "t", SRC_IP: ip, URL: "/login",
		METHOD: "POST", ACTION: action, RULE: rule,
		CREATE_TIME: "2026-10-14 10:00:00", UNIX_ADD_TIME: 1760407200000, Day: 20261014,
		HEADER: "User-Agent: curl", BODY: "a=1", RES_BODY: "ok",
	}
}

// effectSpy 替换五个副作用钩子，记录调用次数与处理日志条数。
type effectSpy struct {
	mu    sync.Mutex
	calls map[string]int
	rows  map[string]int
}

func newEffectSpy() *effectSpy {
	return &effectSpy{calls: map[string]int{}, rows: map[string]int{}}
}

func (s *effectSpy) fn(name string) func([]*innerbean.WebLog) {
	return func(logs []*innerbean.WebLog) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls[name]++
		s.rows[name] += len(logs)
	}
}

func (s *effectSpy) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		n += c
	}
	return n
}

// installEffects 用 spy 替换副作用钩子，返回还原函数。
func installEffects(spy *effectSpy) func() {
	oldIP, oldStats, oldAna, oldKafka, oldFile := logEffectIPFailures, logEffectTrafficStats, logEffectAnalysisStats, logEffectKafkaBatch, logEffectFileBatch
	logEffectIPFailures = spy.fn("ip")
	logEffectTrafficStats = spy.fn("stats")
	logEffectAnalysisStats = spy.fn("analysis")
	logEffectKafkaBatch = spy.fn("kafka")
	logEffectFileBatch = spy.fn("file")
	return func() {
		logEffectIPFailures, logEffectTrafficStats, logEffectAnalysisStats, logEffectKafkaBatch, logEffectFileBatch =
			oldIP, oldStats, oldAna, oldKafka, oldFile
	}
}

func tierRowCounts(t *testing.T, db *gorm.DB) (event, access, payload int64) {
	t.Helper()
	db.Model(&model.SecurityEvent{}).Count(&event)
	db.Model(&model.AccessLog{}).Count(&access)
	db.Model(&model.EventPayload{}).Count(&payload)
	return
}

// resetLedgerTestEnv 保存/还原全局环境。
func resetLedgerTestEnv(t *testing.T, logDB *gorm.DB, mode string) {
	t.Helper()
	savedDB := global.GWAF_LOCAL_LOG_DB
	savedMode := global.GDATA_ACCESS_LOG_MODE
	savedSampler := negSampler
	savedMaxAttempts := ledgerMaxAttempts
	global.GWAF_LOCAL_LOG_DB = logDB
	global.GDATA_ACCESS_LOG_MODE = mode
	negSampler = &sampleReservoir{buckets: map[string]*sampleBucket{}}
	t.Cleanup(func() {
		global.GWAF_LOCAL_LOG_DB = savedDB
		global.GDATA_ACCESS_LOG_MODE = savedMode
		negSampler = savedSampler
		ledgerMaxAttempts = savedMaxAttempts
	})
}

// 正常路径：事件三层齐全、正常请求窄行进，全部确认后台账清空、副作用各一次。
func TestLogLedgerHappyPath(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLedgerTestEnv(t, logDB, "db")
	spy := newEffectSpy()
	defer installEffects(spy)()

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)

	logs := []*innerbean.WebLog{
		ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"),
		ledgerTestLog("n1", "1.2.3.4", "放行", ""),
	}
	m.admit(logs)
	if m.PendingCount() != 1 {
		t.Fatalf("接收后应有 1 个未确认批次，实际 %d", m.PendingCount())
	}

	m.processDue(false)

	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 2 || pl != 1 {
		t.Fatalf("三层行数不对 event/access/payload = %d/%d/%d（期望 1/2/1）", ev, ac, pl)
	}
	if m.PendingCount() != 0 || m.DeadCount() != 0 {
		t.Fatalf("确认后台账应清空，pending=%d dead=%d", m.PendingCount(), m.DeadCount())
	}
	if spy.totalCalls() != 5 {
		t.Fatalf("五个副作用各执行一次，期望 5 次实际 %d (%v)", spy.totalCalls(), spy.calls)
	}
	for name, n := range spy.rows {
		if n != 2 {
			t.Fatalf("副作用 %s 处理日志数应为 2，实际 %d", name, n)
		}
	}
}

// 报文层失败：事件/窄行先行确认，副作用不触发；补建报文表后重试，
// 只补报文层，事件与窄行不复制，副作用恰好一次。
func TestLogLedgerPartialLayerResume(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	// 故意只建两张表，缺 event_payload。
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}); err != nil {
		t.Fatal(err)
	}
	resetLedgerTestEnv(t, logDB, "db")
	spy := newEffectSpy()
	defer installEffects(spy)()

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)

	m.admit([]*innerbean.WebLog{
		ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"),
		ledgerTestLog("n1", "1.2.3.4", "放行", ""),
	})
	m.processDue(false)

	ev, ac, _ := tierRowCounts(t, logDB)
	if ev != 1 || ac != 2 {
		t.Fatalf("事件/窄行应已确认 %d/%d", ev, ac)
	}
	if m.PendingCount() != 1 {
		t.Fatalf("报文层未完成，批次必须保留，pending=%d", m.PendingCount())
	}
	if spy.totalCalls() != 0 {
		t.Fatalf("三层未齐不得触发副作用，实际 %d 次", spy.totalCalls())
	}
	var row logBatchLedger
	ledgerDB.First(&row)
	if row.LayerMask != layerBitEvent|layerBitAccess {
		t.Fatalf("层完成位应为 事件|窄行=%d，实际 %d", layerBitEvent|layerBitAccess, row.LayerMask)
	}
	if row.EffectMask != 0 {
		t.Fatalf("副作用位应全 0，实际 %d", row.EffectMask)
	}

	// 数据库恢复：补建报文表。
	if err := logDB.AutoMigrate(&model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	// 退避未到期：正常一轮不应处理（受控重试节奏）。
	m.processDue(false)
	if spy.totalCalls() != 0 {
		t.Fatalf("退避未到期不应重试")
	}
	// 关停排空/等待到期后处理：忽略退避。
	m.processDue(true)

	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 2 || pl != 1 {
		t.Fatalf("补齐后 event/access/payload = %d/%d/%d（期望 1/2/1），已完成层不得复制", ev, ac, pl)
	}
	if m.PendingCount() != 0 {
		t.Fatalf("补齐后批次应释放，pending=%d", m.PendingCount())
	}
	if spy.totalCalls() != 5 {
		t.Fatalf("副作用应在三层齐后只执行一次，实际 %d", spy.totalCalls())
	}
}

// 模拟进程重启：换一个台账管理器打开同一个台账库，未确认批次继续处理，
// 副作用不重复；已确认删除的批次不重放。
func TestLogLedgerResumeAcrossRestart(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	resetLedgerTestEnv(t, logDB, "db")
	// 「进程一」只接收、不处理（分层表尚未建，模拟故障前已接收的批次留在台账）。
	ledgerDB := openTestGorm(t, "ledger.db")
	m1 := newLogLedgerForTest(ledgerDB)
	m1.admit([]*innerbean.WebLog{
		ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"),
		ledgerTestLog("n2", "5.6.7.8", "放行", ""),
	})

	// 「重启」：日志库表就位，新管理器，新的副作用记录器。
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	spy2 := newEffectSpy()
	defer installEffects(spy2)()
	m2 := newLogLedgerForTest(ledgerDB)
	if m2.PendingCount() != 1 {
		t.Fatalf("重启后应能读到 1 个未确认批次，实际 %d", m2.PendingCount())
	}
	m2.processDue(true)

	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 2 || pl != 1 {
		t.Fatalf("恢复后三层行数 %d/%d/%d（期望 1/2/1）", ev, ac, pl)
	}
	if spy2.totalCalls() != 5 {
		t.Fatalf("恢复处理副作用恰好一次，实际 %d", spy2.totalCalls())
	}
	if m2.PendingCount() != 0 {
		t.Fatalf("恢复后批次应全部释放，pending=%d", m2.PendingCount())
	}

	// 再跑一轮：已确认删除的批次不得重放。
	m2.processDue(true)
	if spy2.totalCalls() != 5 {
		t.Fatalf("已释放批次重跑不得再触发副作用，实际 %d", spy2.totalCalls())
	}
}

// 崩溃在副作用执行之后：完成位已全部持久化、批次尚未删除。
// 下轮（含重启后）三层全部跳过、副作用全部跳过，只做释放，绝不重复。
func TestLogLedgerCrashAfterEffectsReplaysNothing(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLedgerTestEnv(t, logDB, "db")

	ledgerDB := openTestGorm(t, "ledger.db")
	m1 := newLogLedgerForTest(ledgerDB)
	m1.admit([]*innerbean.WebLog{ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi")})
	m1.processDue(true)

	if m1.PendingCount() != 0 {
		t.Fatalf("前置：批次应已确认删除")
	}
	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 1 || pl != 1 {
		t.Fatalf("前置三层 %d/%d/%d", ev, ac, pl)
	}

	// 人为构造「层位+副作用位全落盘但行还在」的崩溃现场。
	spy := newEffectSpy()
	defer installEffects(spy)()
	stuck := logBatchLedger{
		BatchID:    "stuck-batch",
		Payload:    mustEnvelope(t, "db", ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi")),
		Status:     ledgerStatusPending,
		NeedMask:   layerBitEvent | layerBitAccess | layerBitPayload,
		LayerMask:  layerBitEvent | layerBitAccess | layerBitPayload,
		EffectMask: effectBitIPFail | effectBitStats | effectBitAnalysis | effectBitKafka | effectBitFile,
		DueAt:      time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
		UpdatedAt:  time.Now().Unix(),
	}
	if err := ledgerDB.Create(&stuck).Error; err != nil {
		t.Fatal(err)
	}
	m2 := newLogLedgerForTest(ledgerDB)
	m2.processDue(true)

	ev, ac, pl = tierRowCounts(t, logDB)
	if ev != 1 || ac != 1 || pl != 1 {
		t.Fatalf("重放不得复制已完成行 %d/%d/%d（期望 1/1/1）", ev, ac, pl)
	}
	if spy.totalCalls() != 0 {
		t.Fatalf("完成位在的副作用不得重新执行，实际 %d", spy.totalCalls())
	}
	if m2.PendingCount() != 0 {
		t.Fatalf("崩溃现场批次应只做释放，pending=%d", m2.PendingCount())
	}
}

// 决策冻结：重试不再询问蓄水池；SkipPayloadStore 经 JSON 往返后仍不产生报文行。
func TestLogLedgerFrozenDecisions(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLedgerTestEnv(t, logDB, "db")
	spy := newEffectSpy()
	defer installEffects(spy)()

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)

	cc := ledgerTestLog("cc1", "203.0.113.10", "阻止", "CC封禁")
	cc.SkipPayloadStore = true
	normal := ledgerTestLog("n1", "203.0.113.11", "放行", "")
	m.admit([]*innerbean.WebLog{cc, normal})

	pickedBefore := len(negSampler.snapshot())
	if pickedBefore != 1 {
		t.Fatalf("接收分类时蓄水池应采中 1 条正常请求，实际 %d", pickedBefore)
	}

	// 处理多轮（包括 drain 忽略退避），蓄水池内容不得因重试发生变化。
	m.processDue(true)
	m.processDue(true)
	if got := len(negSampler.snapshot()); got != pickedBefore {
		t.Fatalf("重试不得重新采样，蓄水池 %d→%d", pickedBefore, got)
	}

	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 2 || pl != 0 {
		t.Fatalf("CC 窄行保留但报文不写 + 正常请求无事件报文：%d/%d/%d（期望 1/2/0）", ev, ac, pl)
	}
}

// off 档全是正常请求：三层无行可写（need_mask=0），副作用照发、批次确认释放。
func TestLogLedgerOffModeNoLayers(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLedgerTestEnv(t, logDB, "off")
	spy := newEffectSpy()
	defer installEffects(spy)()

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)
	m.admit([]*innerbean.WebLog{
		ledgerTestLog("o1", "1.2.3.4", "放行", ""),
		ledgerTestLog("o2", "1.2.3.4", "放行", ""),
	})
	m.processDue(true)

	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 0 || ac != 0 || pl != 0 {
		t.Fatalf("off 档正常请求三层都不应有行：%d/%d/%d", ev, ac, pl)
	}
	if spy.totalCalls() != 5 || spy.rows["stats"] != 2 {
		t.Fatalf("全量副作用仍应执行一次（stats 吃全量 2 条）：calls=%d statsRows=%d", spy.totalCalls(), spy.rows["stats"])
	}
	if m.PendingCount() != 0 {
		t.Fatalf("无层可写的批次也应确认释放，pending=%d", m.PendingCount())
	}
	if len(negSampler.snapshot()) != 0 {
		t.Fatal("off 档蓄水池不应被询问")
	}
}

// 持续失败：达到最大尝试次数转死信，原文与错误保留、计数可观察；不再参与重试。
func TestLogLedgerDeadLetter(t *testing.T) {
	logDB := openTestGorm(t, "log.db") // 一张分层表都不建，所有层写入必失败
	resetLedgerTestEnv(t, logDB, "db")
	spy := newEffectSpy()
	defer installEffects(spy)()
	ledgerMaxAttempts = 2

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)
	m.admit([]*innerbean.WebLog{ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi")})

	m.processDue(true) // attempts 1
	if m.PendingCount() != 1 || m.DeadCount() != 0 {
		t.Fatalf("首次失败应保留 pending：pending=%d dead=%d", m.PendingCount(), m.DeadCount())
	}
	m.processDue(true) // attempts 2 → dead
	if m.PendingCount() != 0 || m.DeadCount() != 1 {
		t.Fatalf("达到上限应转死信：pending=%d dead=%d", m.PendingCount(), m.DeadCount())
	}
	if spy.totalCalls() != 0 {
		t.Fatalf("死信批次从未完成三层，副作用不应执行")
	}
	var dead logBatchLedger
	if err := ledgerDB.Where("status = ?", ledgerStatusDead).First(&dead).Error; err != nil {
		t.Fatalf("死信行应保留: %v", err)
	}
	if dead.LastError == "" || len(dead.Payload) == 0 {
		t.Fatal("死信必须保留最后错误与批次原文")
	}
	// 诊断可观察
	items := m.diagCollect()
	if items["dead"] != 1 || items["pending"] != 0 {
		t.Fatalf("诊断计数不对: %v", items)
	}
	// 死信不再被处理
	m.processDue(true)
	if spy.totalCalls() != 0 {
		t.Fatal("死信不得再被自动重试")
	}
}

// 退避节奏：失败后 due_at 推到未来，未到期的 processDue 不处理。
func TestLogLedgerBackoffDueRespected(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	resetLedgerTestEnv(t, logDB, "db")
	spy := newEffectSpy()
	defer installEffects(spy)()

	ledgerDB := openTestGorm(t, "ledger.db")
	m := newLogLedgerForTest(ledgerDB)
	m.admit([]*innerbean.WebLog{ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi")})
	before := time.Now().Unix()
	m.processDue(false)

	var row logBatchLedger
	ledgerDB.Where("status = ?", ledgerStatusPending).First(&row)
	if row.Attempts != 1 || row.DueAt <= before {
		t.Fatalf("退避应把 due_at 推到未来：attempts=%d dueAt=%d now=%d", row.Attempts, row.DueAt, before)
	}
	// 立刻再跑正常轮询：due 未到，不应再尝试（attempts 不增加）。
	m.processDue(false)
	ledgerDB.Where("status = ?", ledgerStatusPending).First(&row)
	if row.Attempts != 1 {
		t.Fatalf("未到期不应重试，attempts=%d", row.Attempts)
	}
}

// mustEnvelope 构造一个序列化后的批次信封（模拟崩溃现场）。
func mustEnvelope(t *testing.T, mode string, logs ...*innerbean.WebLog) []byte {
	t.Helper()
	decisions, _, _, _ := classifyForTier(logs)
	data, err := json.Marshal(&logBatchEnvelope{Mode: mode, Logs: logs, Decide: decisions})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// ── 集成：真实运行队列 → runLogQueueOnce → 台账确认 → 关停排空 ──

// resetLogQueueEnv 保存/恢复消费协程触碰的全部全局状态。
func resetLogQueueEnv(t *testing.T, logDB *gorm.DB) {
	t.Helper()
	savedDB := global.GWAF_LOCAL_LOG_DB
	savedMode := global.GDATA_ACCESS_LOG_MODE
	savedPersist := global.GCONFIG_LOG_PERSIST_ENABLED
	savedQ := global.GQEQUE_LOG_DB
	savedSignal := global.GWAF_QUEUE_SHUTDOWN_SIGNAL
	savedMeasure := global.GWAF_MEASURE_PROCESS_DEQUEENGINE
	savedSampler := negSampler
	savedOpener := logLedgerOpener
	savedDrain := logDrainMaxWait
	savedPoll := logDrainPoll
	global.GWAF_LOCAL_LOG_DB = logDB
	global.GDATA_ACCESS_LOG_MODE = "db"
	global.GCONFIG_LOG_PERSIST_ENABLED = 1
	global.GQEQUE_LOG_DB = queue.NewQueue()
	global.GWAF_QUEUE_SHUTDOWN_SIGNAL = make(chan struct{})
	global.GWAF_MEASURE_PROCESS_DEQUEENGINE = cache.InitWafOnlyLockWrite()
	negSampler = &sampleReservoir{buckets: map[string]*sampleBucket{}}
	resetLogLedgerForTest()
	t.Cleanup(func() {
		global.GWAF_LOCAL_LOG_DB = savedDB
		global.GDATA_ACCESS_LOG_MODE = savedMode
		global.GCONFIG_LOG_PERSIST_ENABLED = savedPersist
		global.GQEQUE_LOG_DB = savedQ
		global.GWAF_QUEUE_SHUTDOWN_SIGNAL = savedSignal
		global.GWAF_MEASURE_PROCESS_DEQUEENGINE = savedMeasure
		negSampler = savedSampler
		logLedgerOpener = savedOpener
		logDrainMaxWait = savedDrain
		logDrainPoll = savedPoll
		resetLogLedgerForTest()
	})
}

func resetLogLedgerForTest() {
	logLedgerMu.Lock()
	logLedgerActive = nil
	logLedgerMu.Unlock()
}

// installTempLedgerOpener 让生产懒打开路径返回临时台账库上的管理器。
func installTempLedgerOpener(ledgerDB *gorm.DB) {
	logLedgerOpener = func() (*logLedgerManager, error) {
		return newLogLedgerForTest(ledgerDB), nil
	}
}

// 端到端：运行队列里的 WebLog 经一轮消费后三层落齐、副作用一次、台账与队列双空。
func TestLogQueueEndToEndDurable(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLogQueueEnv(t, logDB)
	ledgerDB := openTestGorm(t, "ledger.db")
	installTempLedgerOpener(ledgerDB)
	spy := newEffectSpy()
	defer installEffects(spy)()

	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"))
	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("n1", "1.2.3.4", "放行", ""))
	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("n2", "5.6.7.8", "放行", ""))

	runLogQueueOnce(false)

	if global.GQEQUE_LOG_DB.Size() != 0 {
		t.Fatal("运行队列应被取空")
	}
	ev, ac, pl := tierRowCounts(t, logDB)
	// 报文 3 = 1 条事件报文 + 2 条正常请求在首轮蓄水池到期刷出的 sample（与生产首轮行为一致）。
	if ev != 1 || ac != 3 || pl != 3 {
		t.Fatalf("三层行数 %d/%d/%d（期望 1/3/3）", ev, ac, pl)
	}
	var eventPayloads, samplePayloads int64
	logDB.Model(&model.EventPayload{}).Where("kind = ?", PayloadKindEvent).Count(&eventPayloads)
	logDB.Model(&model.EventPayload{}).Where("kind = ?", PayloadKindSample).Count(&samplePayloads)
	if eventPayloads != 1 || samplePayloads != 2 {
		t.Fatalf("报文归属不对 event=%d sample=%d（期望 1/2）", eventPayloads, samplePayloads)
	}
	if m := currentLogLedger(); m == nil || m.PendingCount() != 0 {
		t.Fatalf("批次应已确认释放：%+v", m)
	}
	if spy.totalCalls() != 5 || spy.rows["kafka"] != 3 {
		t.Fatalf("副作用各一次且覆盖全量 3 条：calls=%d kafkaRows=%d", spy.totalCalls(), spy.rows["kafka"])
	}
}

// 未开启持久化：台账不打开，旧路径行为（无批次落台账、副作用照发）。
func TestLogQueueEndToEndPersistDisabled(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLogQueueEnv(t, logDB)
	global.GCONFIG_LOG_PERSIST_ENABLED = 0
	openerCalled := false
	logLedgerOpener = func() (*logLedgerManager, error) {
		openerCalled = true
		return newLogLedgerForTest(openTestGorm(t, "unused.db")), nil
	}
	spy := newEffectSpy()
	defer installEffects(spy)()

	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"))
	runLogQueueOnce(false)

	if openerCalled || currentLogLedger() != nil {
		t.Fatal("未开启持久化不应打开台账")
	}
	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 0 || ac != 0 || pl != 0 {
		t.Fatalf("关闭持久化时三层都不应落库：%d/%d/%d", ev, ac, pl)
	}
	if spy.totalCalls() != 5 {
		t.Fatalf("旧路径副作用不受影响，期望 5 次实际 %d", spy.totalCalls())
	}
}

// 关停排空超时：日志库持续不可用时，运行队列先全部落入台账，未确认批次保留到下次启动。
func TestLogQueueDrainTimeoutKeepsLedger(t *testing.T) {
	logDB := openTestGorm(t, "log.db") // 分层表一张都不建
	resetLogQueueEnv(t, logDB)
	ledgerDB := openTestGorm(t, "ledger.db")
	installTempLedgerOpener(ledgerDB)
	spy := newEffectSpy()
	defer installEffects(spy)()
	logDrainMaxWait = 300 * time.Millisecond
	logDrainPoll = 20 * time.Millisecond

	for i := 0; i < 3; i++ {
		global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("e"+itoa(i), "1.2.3.4", "阻止", "SQLi"))
	}
	runLogQueueOnce(false) // 接收成功、三层失败 → pending
	drainLogQueueOnShutdown()

	if global.GQEQUE_LOG_DB.Size() != 0 {
		t.Fatal("排空应先把运行队列取空")
	}
	// 3 条日志在同一批接收，台账里是 1 个未确认批次行（计数单位是批次而非日志条）。
	m := currentLogLedger()
	if m == nil || m.PendingCount() != 1 {
		t.Fatalf("未确认批次应保留在台账：pending=%v", m)
	}
	var left logBatchLedger
	if err := ledgerDB.Where("status = ?", ledgerStatusPending).First(&left).Error; err != nil {
		t.Fatalf("未确认批次原文应保留: %v", err)
	}
	var env logBatchEnvelope
	if err := json.Unmarshal(left.Payload, &env); err != nil || len(env.Logs) != 3 {
		t.Fatalf("台账批次应含 3 条原文日志：%d err=%v", len(env.Logs), err)
	}
	if spy.totalCalls() != 0 {
		t.Fatal("未确认批次不得触发副作用")
	}
}

// 关停排空中数据库恢复：台账忽略退避继续重试，收敛后批次确认释放。
func TestLogQueueDrainRecovers(t *testing.T) {
	logDB := openTestGorm(t, "log.db") // 起初没有分层表
	resetLogQueueEnv(t, logDB)
	ledgerDB := openTestGorm(t, "ledger.db")
	installTempLedgerOpener(ledgerDB)
	spy := newEffectSpy()
	defer installEffects(spy)()
	logDrainMaxWait = 3 * time.Second
	logDrainPoll = 20 * time.Millisecond

	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"))
	runLogQueueOnce(false) // 失败进入退避（正常轮询未到期不会重试）
	if m := currentLogLedger(); m.PendingCount() != 1 {
		t.Fatal("前置：应有 1 个未确认批次")
	}
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	drainLogQueueOnShutdown()

	if m := currentLogLedger(); m.PendingCount() != 0 {
		t.Fatalf("恢复后排空应收敛，pending=%d", m.PendingCount())
	}
	ev, ac, pl := tierRowCounts(t, logDB)
	if ev != 1 || ac != 1 || pl != 1 {
		t.Fatalf("三层补齐 %d/%d/%d（期望 1/1/1）", ev, ac, pl)
	}
	if spy.totalCalls() != 5 {
		t.Fatalf("恢复后副作用恰好一次，实际 %d", spy.totalCalls())
	}
}

// WaitLogQueueDrain：消费协程收到关闭信号后完成排空，等待方拿到 true。
func TestWaitLogQueueDrainConverges(t *testing.T) {
	logDB := openTestGorm(t, "log.db")
	if err := logDB.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
		t.Fatal(err)
	}
	resetLogQueueEnv(t, logDB)
	ledgerDB := openTestGorm(t, "ledger.db")
	installTempLedgerOpener(ledgerDB)
	spy := newEffectSpy()
	defer installEffects(spy)()
	logDrainMaxWait = 5 * time.Second

	global.GQEQUE_LOG_DB.Enqueue(ledgerTestLog("e1", "1.2.3.4", "阻止", "SQLi"))
	go ProcessLogDequeEngine()
	time.Sleep(150 * time.Millisecond) // 让协程完成换代并处理一轮
	close(global.GWAF_QUEUE_SHUTDOWN_SIGNAL)
	if !WaitLogQueueDrain() {
		t.Fatal("队列无积压时排空等待应成功返回")
	}
	if spy.totalCalls() != 5 {
		t.Fatalf("排空处理副作用恰好一次，实际 %d", spy.totalCalls())
	}
}
