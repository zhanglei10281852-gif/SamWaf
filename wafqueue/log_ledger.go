package wafqueue

// 日志批次「可恢复确认」台账。
//
// 背景：日志从运行队列取出后是先出队后落库的，数据库短暂不可用或进程退出时，
// 已被防护引擎接收的最后一批攻击/访问日志只换来一行写入告警，行本身丢失。
// 台账把「接收 → 三层落库 → 确认释放」做成可崩溃恢复的流程：
//
//   - admit：批次从运行队列取出后，先连同冻结的分层决策整体写入本地台账（pending），
//     这一刻即「已接收」。台账固定为本地加密 SQLite（data/log_ledger.db），
//     独立于可切 MySQL/PostgreSQL 的日志库——日志库挂了台账仍可读可写。
//   - processDue：按台账顺序重放 pending 批次。安全事件/访问窄行/报文三层各有完成位，
//     只补未完成的层；三层写入全部是主键 DoNothing，已存在的行只跳过、绝不复制。
//   - 副作用（IP 失败次数、流量/分析统计、Kafka、文件日志）在三层确认后才发生，
//     每个副作用有自己的「已完成」位：先落位再执行，数据库重试/关停排空/重启恢复
//     都不会重复计数或重复外发（崩溃恰好发生在落位与执行之间时该副作用至多丢失一次，
//     这是「不得重复」要求下唯一安全的取舍；正常关停路径同步执行，不受此窗口影响）。
//   - 三层与副作用全部完成后删除台账行，批次才「永久释放」。
//   - 数据库临时失败：未确认批次保留，按指数退避受控重试；超过最大尝试次数转为 dead
//     死信，原文与最后错误保留在台账里并计入运行诊断，持续不可恢复的内容可观察。
//   - 进程在任何时刻退出：pending 批次下次启动继续处理；已完成层靠完成位+主键跳过，
//     已完成副作用靠完成位跳过，已删除（已确认）的批次不会重放。
//
// 台账使用 synchronous=FULL：台账的每次接收/确认都要扛得住断电，WAL 下每批次一次
// fsync；消费节奏为每 100ms 一批（≤101 行），开销可忽略，不牺牲批量吞吐。

import (
	"SamWaf/common/diagstat"
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 三层完成位。NeedMask 为「按接收时档位本批应写哪些层」；LayerMask 为已确认的层。
const (
	layerBitEvent   = 1 << 0 // security_event 安全事件窄行
	layerBitAccess  = 1 << 1 // access_log 访问窄行
	layerBitPayload = 1 << 2 // event_payload 报文层（事件/观察名单；负样本仍由蓄水池自行刷）
)

// 副作用完成位。顺序即原消费协程的发生顺序，落位（持久化该位）后才执行。
const (
	effectBitIPFail   = 1 << 0 // IP 失败状态码计数（wafipban）
	effectBitStats    = 1 << 1 // 流量/主机/IP/城市等天小时聚合
	effectBitAnalysis = 1 << 2 // 分析层天级汇总
	effectBitKafka    = 1 << 3 // Kafka 外发
	effectBitFile     = 1 << 4 // 文件日志外发
)

const (
	// ledgerTableName 台账表名。
	ledgerTableName = "log_batch_ledger"
	// ledgerFileName 台账库文件名（固定放在 data 目录，与引擎库同生共死）。
	ledgerFileName = "log_ledger.db"
	// ledgerStatusPending 未确认：三层/副作用尚有未完成项，等待到期重试。
	ledgerStatusPending = "pending"
	// ledgerStatusDead 死信：超过最大尝试次数仍无法确认，原文保留供排查，不再自动重试。
	ledgerStatusDead = "dead"
	// dueRowsPerTick 正常一轮最多处理多少条到期批次（每条 ≤101 条日志，追赶故障积压用）。
	dueRowsPerTick = 100
	// dueRowsPerDrain 关停排空一轮最多取多少条（排空时循环多轮直到收敛或超时）。
	dueRowsPerDrain = 500
	// deadRetainDays 死信保留天数（与安全事件保留期量级一致，过后启动时清理）。
	deadRetainDays = 180
)

// 退避与放弃阈值（包级变量，单测可调小快速进入死信）。
// 退避 1s→2s→4s→… 封顶 60s；4320 次 ≈ 连续故障 3 天转为死信。
var (
	ledgerBackoffBase    = time.Second
	ledgerBackoffMax     = time.Minute
	ledgerMaxAttempts    = 4320
	ledgerDeadLastErrLen = 2000
)

// logBatchLedger 一个待确认批次的台账行。Payload 为批次信封（日志原文 + 冻结决策）。
type logBatchLedger struct {
	ID         int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	BatchID    string `gorm:"size:64;uniqueIndex" json:"batch_id"`
	Payload    []byte `json:"payload"`
	Status     string `gorm:"size:16;index:idx_lbl_due,priority:1" json:"status"`
	NeedMask   int    `gorm:"column:need_mask" json:"need_mask"`
	LayerMask  int    `gorm:"column:layer_mask" json:"layer_mask"`
	EffectMask int    `gorm:"column:effect_mask" json:"effect_mask"`
	Attempts   int    `json:"attempts"`
	LastError  string `gorm:"size:2000" json:"last_error"`
	DueAt      int64  `gorm:"index:idx_lbl_due,priority:2" json:"due_at"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (logBatchLedger) TableName() string { return ledgerTableName }

// logBatchEnvelope 批次持久化报文：日志原文 + 每条日志接收时冻结的分层决策 + 接收时档位。
type logBatchEnvelope struct {
	BatchID string              `json:"batch_id"`
	Mode    string              `json:"mode"`
	Logs    []*innerbean.WebLog `json:"logs"`
	Decide  []logTierDecision   `json:"decide"`
}

// logLedgerManager 批次台账管理器。只在日志队列消费协程内使用（关停排空也是它），
// 计数用原子量仅供诊断协程读取。
type logLedgerManager struct {
	db            *gorm.DB
	pendingCountN atomic.Int64
	deadCountN    atomic.Int64
}

var (
	logLedgerMu     sync.Mutex
	logLedgerActive *logLedgerManager
)

// logLedgerOpener 台账打开器（生产指向 data/log_ledger.db，单测替换为临时库）。
var logLedgerOpener = func() (*logLedgerManager, error) {
	path := filepath.Join(utils.GetCurrentDir(), "data", ledgerFileName)
	return openLogLedger(path)
}

// ensureLogLedger 懒打开台账（消费协程发现持久化开关打开时调用；开关可能在运行期热切换）。
// 台账库自身不可用时返回 nil：调用方退回改造前的尽力而为路径，不阻断流量。
func ensureLogLedger() *logLedgerManager {
	logLedgerMu.Lock()
	defer logLedgerMu.Unlock()
	if logLedgerActive != nil {
		return logLedgerActive
	}
	m, err := logLedgerOpener()
	if err != nil {
		zlog.Error("日志批次确认台账打开失败，本次运行回退为非持久化尽力写入", "error", err.Error())
		return nil
	}
	logLedgerActive = m
	return m
}

// currentLogLedger 返回已打开的台账（可能为 nil：本进程从未开启持久化）。
func currentLogLedger() *logLedgerManager {
	logLedgerMu.Lock()
	defer logLedgerMu.Unlock()
	return logLedgerActive
}

// openLogLedger 打开/创建台账库并建表。总是本地加密 SQLite，与日志库引擎无关。
func openLogLedger(path string) (*logLedgerManager, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return nil, fmt.Errorf("创建台账目录失败: %w", err)
		}
	}
	dsn := fmt.Sprintf("%s?_db_key=%s", path, url.QueryEscape(global.GWAF_PWD_LEDGERDB))
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("打开台账库失败: %w", err)
	}
	// 可靠性优先：WAL + synchronous=FULL（接收/确认必须扛断电），锁竞争等待 5s。
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA temp_store=MEMORY;",
		"PRAGMA wal_autocheckpoint=1000;",
	} {
		if perr := db.Exec(pragma).Error; perr != nil {
			zlog.Warn("台账库 pragma 设置失败", "pragma", pragma, "error", perr.Error())
		}
	}
	if sqlDB, derr := db.DB(); derr == nil {
		// 只有日志队列一个写者；单连接彻底避开 file lock 竞争。
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}
	if err := db.AutoMigrate(&logBatchLedger{}); err != nil {
		return nil, fmt.Errorf("台账表迁移失败: %w", err)
	}
	m := &logLedgerManager{db: db}
	m.loadCounters()
	// 重启恢复：把未确认批次的退避时间清零，让它们在首轮立即继续处理，
	// 不必等完上个进程设置的退避（attempts/last_error 保留，持续失败仍会累计到死信）。
	if err := db.Model(&logBatchLedger{}).
		Where("status = ? and due_at > 0", ledgerStatusPending).
		Update("due_at", 0).Error; err != nil {
		zlog.Warn("重置未确认日志批次的退避时间失败，批次仍会按原退避到期处理", "error", err.Error())
	}
	m.pruneDead()
	diagstat.Register("log_ledger", m.diagCollect)
	zlog.Info("日志批次确认台账已就绪", "path", path, "pending", m.pendingCountN.Load(), "dead", m.deadCountN.Load())
	return m, nil
}

// newLogLedgerForTest 单测用：直接给一个已打开的 gorm 台账库。
func newLogLedgerForTest(db *gorm.DB) *logLedgerManager {
	m := &logLedgerManager{db: db}
	if err := db.AutoMigrate(&logBatchLedger{}); err == nil {
		m.loadCounters()
	}
	return m
}

// PendingCount 未确认（含退避等待中）批次数。
func (m *logLedgerManager) PendingCount() int64 { return m.pendingCountN.Load() }

// DeadCount 死信批次数。
func (m *logLedgerManager) DeadCount() int64 { return m.deadCountN.Load() }

func (m *logLedgerManager) loadCounters() {
	var pending, dead int64
	m.db.Model(&logBatchLedger{}).Where("status = ?", ledgerStatusPending).Count(&pending)
	m.db.Model(&logBatchLedger{}).Where("status = ?", ledgerStatusDead).Count(&dead)
	m.pendingCountN.Store(pending)
	m.deadCountN.Store(dead)
}

// pruneDead 清理超过保留期的死信（每次启动一次），避免故障原文无限堆积。
func (m *logLedgerManager) pruneDead() {
	cutoff := time.Now().Add(-deadRetainDays * 24 * time.Hour).Unix()
	tx := m.db.Where("status = ? and updated_at < ?", ledgerStatusDead, cutoff).Delete(&logBatchLedger{})
	if tx.Error == nil && tx.RowsAffected > 0 {
		zlog.Info("清理过期日志批次死信", "条数", tx.RowsAffected)
		m.deadCountN.Add(-tx.RowsAffected)
	}
}

// diagCollect 运行诊断计量（diagstat 约定 collector 只能做内存级读取）。
func (m *logLedgerManager) diagCollect() map[string]int64 {
	return map[string]int64{
		"pending": m.pendingCountN.Load(),
		"dead":    m.deadCountN.Load(),
	}
}

// admit 把一批日志接收到台账：分类一次（蓄水池 Pick 一次）、冻结决策、整体落台账为 pending。
// 失败时不能丢批：退回改造前的尽力而为路径（直接写库+副作用，各步只告警）。
func (m *logLedgerManager) admit(logs []*innerbean.WebLog) {
	chunkSize := int(global.GDATA_BATCH_INSERT) + 1
	if chunkSize <= 0 {
		chunkSize = 101
	}
	for start := 0; start < len(logs); start += chunkSize {
		end := start + chunkSize
		if end > len(logs) {
			end = len(logs)
		}
		m.admitChunk(logs[start:end])
	}
}

func (m *logLedgerManager) admitChunk(chunk []*innerbean.WebLog) {
	decisions, events, accesses, payloads := classifyForTier(chunk)
	needMask := 0
	if len(events) > 0 {
		needMask |= layerBitEvent
	}
	if len(accesses) > 0 {
		needMask |= layerBitAccess
	}
	if len(payloads) > 0 {
		needMask |= layerBitPayload
	}
	env := logBatchEnvelope{
		BatchID: uuid.GenUUID(),
		Mode:    global.GDATA_ACCESS_LOG_MODE,
		Logs:    chunk,
		Decide:  decisions,
	}
	data, err := json.Marshal(&env)
	if err != nil {
		zlog.Error("日志批次信封序列化失败，该批走尽力而为路径", "条数", len(chunk), "error", err.Error())
		processClassifiedBestEffort(chunk, events, accesses, payloads)
		return
	}
	now := time.Now().Unix()
	row := &logBatchLedger{
		BatchID:   env.BatchID,
		Payload:   data,
		Status:    ledgerStatusPending,
		NeedMask:  needMask,
		DueAt:     now,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := m.db.Create(row).Error; err != nil {
		// 台账写不进（磁盘满/库损坏）：保证不丢数据，退回旧路径。
		// 该批分类已发生（蓄水池 Pick 已计入），不能再走 storeTiered 二次采样，
		// 直接用本次分好的三层行写入。
		zlog.Error("日志批次接收落台账失败，该批走尽力而为路径", "条数", len(chunk), "error", err.Error())
		processClassifiedBestEffort(chunk, events, accesses, payloads)
		return
	}
	m.pendingCountN.Add(1)
}

// processDue 处理到期未确认批次。drain=true 时忽略退避时间（关停排空/恢复追赶时调用方控节奏）。
func (m *logLedgerManager) processDue(drain bool) {
	limit := dueRowsPerTick
	if drain {
		limit = dueRowsPerDrain
	}
	q := m.db.Where("status = ?", ledgerStatusPending)
	if !drain {
		q = q.Where("due_at <= ?", time.Now().Unix())
	}
	var rows []*logBatchLedger
	if err := q.Order("id asc").Limit(limit).Find(&rows).Error; err != nil {
		zlog.Warn("读取待确认日志批次失败", "error", err.Error())
		return
	}
	for _, row := range rows {
		m.processRow(row)
	}
}

// processRow 处理单个批次：补齐缺失层 → 三层齐后按位执行副作用 → 删除确认。
// 任何一步失败都保留行并登记退避，绝不丢给一行告警了事。
func (m *logLedgerManager) processRow(row *logBatchLedger) {
	var env logBatchEnvelope
	if err := json.Unmarshal(row.Payload, &env); err != nil {
		// 信封损坏是永久性失败：重试没有意义，直接死信保留现场。
		m.markDead(row, "批次信封损坏无法解析: "+err.Error())
		return
	}
	events, accesses, payloads := rebuildTierRows(env.Logs, env.Decide, env.Mode)

	// ── 第一层：只补未确认的层，已确认层完全不重发（跨进程重启同样成立）──
	layerMask := row.LayerMask
	var firstLayerErr error
	if row.NeedMask&layerBitEvent != 0 && layerMask&layerBitEvent == 0 && len(events) > 0 {
		if err := conflictIgnoreInsert(events); err != nil {
			firstLayerErr = fmt.Errorf("安全事件落库: %w", err)
		} else {
			layerMask |= layerBitEvent
		}
	}
	if row.NeedMask&layerBitAccess != 0 && layerMask&layerBitAccess == 0 && len(accesses) > 0 {
		if err := conflictIgnoreInsert(accesses); err != nil {
			if firstLayerErr == nil {
				firstLayerErr = fmt.Errorf("访问窄行落库: %w", err)
			}
		} else {
			layerMask |= layerBitAccess
		}
	}
	if row.NeedMask&layerBitPayload != 0 && layerMask&layerBitPayload == 0 && len(payloads) > 0 {
		if err := insertPayloads(payloads); err != nil {
			if firstLayerErr == nil {
				firstLayerErr = fmt.Errorf("报文落库: %w", err)
			}
		} else {
			layerMask |= layerBitPayload
		}
	}
	if firstLayerErr != nil {
		m.scheduleRetry(row, layerMask, row.EffectMask, firstLayerErr)
		return
	}

	// ── 第二层：三层已齐（或本批本就无层可写），副作用按位执行。
	// 先一次性持久化「本轮新补齐的层位 + 尚未执行的副作用位」，再调用副作用：
	// 任何重放路径（库重试/关停/重启）见到层位/副作用位就跳过，
	// 保证 IP 失败次数、流量与分析统计、Kafka、文件日志都只发生一次。
	// 崩溃恰好发生在落位与执行之间时未执行的副作用至多丢失一次——这是「不得重复」
	// 要求下唯一安全的取舍；有序关停路径同步执行完毕才返回，不受此窗口影响。
	// 副作用位合并为一次提交是为了把每批次的台账 fsync 压到最少（接收/落位/释放各一次）。
	newEffectMask := row.EffectMask | effectBitIPFail | effectBitStats | effectBitAnalysis | effectBitKafka | effectBitFile
	if layerMask != row.LayerMask || newEffectMask != row.EffectMask {
		if err := m.db.Model(&logBatchLedger{}).Where("id = ?", row.ID).Updates(map[string]interface{}{
			"layer_mask":  layerMask,
			"effect_mask": newEffectMask,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
			m.scheduleRetry(row, row.LayerMask, row.EffectMask, fmt.Errorf("完成位落台账失败: %w", err))
			return
		}
	}
	m.runPendingEffects(row.EffectMask, newEffectMask, env.Logs)

	// ── 第三层：全部完成，永久释放（删除台账行）──
	if err := m.db.Delete(row).Error; err != nil {
		// 删除失败不影响正确性：下次重放三层靠 DoNothing、副作用靠完成位，全部跳过；
		// 完成位已落盘，保留行等下轮删除即可，不登记 last_error 噪声。
		zlog.Warn("已确认日志批次的台账行删除失败，下轮清理", "batch", row.BatchID, "error", err.Error())
		return
	}
	m.pendingCountN.Add(-1)
}

// runPendingEffects 只执行 oldMask→newMask 之间新置位、因此本进程尚未执行过的副作用，
// 顺序与改造前的消费协程一致。
func (m *logLedgerManager) runPendingEffects(oldMask, newMask int, logs []*innerbean.WebLog) {
	steps := []struct {
		bit int
		fn  func([]*innerbean.WebLog)
	}{
		{effectBitIPFail, logEffectIPFailures},
		{effectBitStats, logEffectTrafficStats},
		{effectBitAnalysis, logEffectAnalysisStats},
		{effectBitKafka, logEffectKafkaBatch},
		{effectBitFile, logEffectFileBatch},
	}
	for _, step := range steps {
		if oldMask&step.bit == 0 && newMask&step.bit != 0 {
			step.fn(logs)
		}
	}
}

// scheduleRetry 保留未确认批次并安排受控退避；达到上限转死信。
func (m *logLedgerManager) scheduleRetry(row *logBatchLedger, layerMask, effectMask int, cause error) {
	attempts := row.Attempts + 1
	if attempts >= ledgerMaxAttempts {
		m.markDead(row, fmt.Sprintf("重试 %d 次仍未确认: %v", attempts, cause))
		return
	}
	wait := ledgerBackoffBase << min(attempts-1, 6)
	if wait <= 0 || wait > ledgerBackoffMax {
		wait = ledgerBackoffMax
	}
	now := time.Now()
	dueAt := now.Add(wait).Unix()
	errText := cause.Error()
	if len(errText) > ledgerDeadLastErrLen {
		errText = errText[:ledgerDeadLastErrLen]
	}
	// 前 5 次每次都留痕，之后每 10 次一条，避免数据库长故障时告警刷屏。
	if attempts <= 5 || attempts%10 == 0 {
		zlog.Warn("日志批次未确认，保留并退避重试",
			"batch", row.BatchID, "attempts", attempts, "layers", fmt.Sprintf("%d/%d", layerMask, row.NeedMask),
			"retry_in", wait.String(), "error", errText)
	}
	if err := m.db.Model(&logBatchLedger{}).Where("id = ?", row.ID).Updates(map[string]interface{}{
		"layer_mask":  layerMask,
		"effect_mask": effectMask,
		"attempts":    attempts,
		"last_error":  errText,
		"due_at":      dueAt,
		"updated_at":  now.Unix(),
	}).Error; err != nil {
		zlog.Error("日志批次退避状态落台账失败", "batch", row.BatchID, "error", err.Error())
	}
}

// markDead 批次转死信：状态翻转、计数迁移、错误原文留存、显式错误日志（可观察）。
func (m *logLedgerManager) markDead(row *logBatchLedger, reason string) {
	now := time.Now().Unix()
	if len(reason) > ledgerDeadLastErrLen {
		reason = reason[:ledgerDeadLastErrLen]
	}
	tx := m.db.Model(&logBatchLedger{}).Where("id = ? and status = ?", row.ID, ledgerStatusPending).
		Updates(map[string]interface{}{
			"status":     ledgerStatusDead,
			"last_error": reason,
			"due_at":     0,
			"updated_at": now,
		})
	if tx.Error != nil {
		zlog.Error("日志批次死信状态落台账失败", "batch", row.BatchID, "error", tx.Error.Error())
		return
	}
	// 只有这一次确实把 pending 翻成 dead 才迁移计数（单一消费协程下恒为 1，防御性校验）。
	if tx.RowsAffected > 0 {
		m.pendingCountN.Add(-1)
		m.deadCountN.Add(1)
	}
	zlog.Error("日志批次持续无法确认，已转为死信并保留原文",
		"batch", row.BatchID, "id", row.ID, "attempts", row.Attempts,
		"retain_days", deadRetainDays, "reason", reason)
}

// storeTieredRowsBestEffort 台账不可用时的退路：三层各自一条批量语句、失败只告警，
// 行为与改造前 storeTiered 完全一致（用的是接收时已分好的行，不二次采样）。
func storeTieredRowsBestEffort(events []*model.SecurityEvent, accesses []*model.AccessLog, payloads []*model.EventPayload) {
	if len(events) > 0 {
		if err := conflictIgnoreInsert(events); err != nil {
			zlog.Warn("安全事件落库失败", "条数", len(events), "error", err.Error())
		}
	}
	if len(accesses) > 0 {
		if err := conflictIgnoreInsert(accesses); err != nil {
			zlog.Warn("访问日志落库失败", "条数", len(accesses), "error", err.Error())
		}
	}
	storePayloads(payloads)
}
