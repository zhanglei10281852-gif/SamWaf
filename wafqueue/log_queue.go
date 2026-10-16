package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafipban"
	"SamWaf/waftask"
	"strconv"
	"sync"
	"time"
)

/*
*
处理Log队列信息

两条路径：
  - 开启日志持久化（GCONFIG_LOG_PERSIST_ENABLED=1，默认）：批次取出后先进本地确认台账
    （log_ledger.go），安全事件/访问窄行/报文三层按接收时档位补齐、副作用（IP 失败计数、
    流量与分析统计、Kafka、文件日志）按完成位只执行一次，全部确认才永久释放；
    数据库临时故障受控退避重试，进程退出后下次启动继续未确认批次，持续失败转死信。
  - 未开启持久化或台账不可用：维持改造前的尽力而为路径（processWebLogsBestEffort），
    非落库行为与此前完全一致。
*/

// 有序关停排空参数：关停时引擎已先于队列停止生产，这里只排空已接收内容。
// 为包级变量（非 const）：语义上是常量，仅单测缩短超时用。
var (
	logDrainMaxWait = 30 * time.Second // 排空最长等待；超时未确认的批次留在台账，下次启动继续
	logDrainPoll    = 50 * time.Millisecond
	logDrainEmptyOK = 2 // 连续多少轮「队列空+无未确认」才算收敛，挡住关停瞬间的尾巴
)

// 消费协程生命周期（带「代」）：NeverExit 会在 panic 后重启协程，
// 每一代用独立 done 通道，WaitLogQueueDrain 因此不会把崩溃退出误判成排空完成。
var (
	logProcMu     sync.Mutex
	logProcGen    uint64
	logProcDoneCh = make(chan struct{})
)

// resetLogProcessorLifecycle 初始化队列时重置生命周期通道。
func resetLogProcessorLifecycle() {
	logProcMu.Lock()
	defer logProcMu.Unlock()
	logProcGen++
	logProcDoneCh = make(chan struct{})
}

// WaitLogQueueDrain 等待日志消费协程完成关停排空，返回 false 表示等待超时。
// 在 main 的关停序列里 close(关闭信号) 之后调用。
func WaitLogQueueDrain() bool {
	deadline := time.Now().Add(logDrainMaxWait + 5*time.Second)
	for {
		logProcMu.Lock()
		ch := logProcDoneCh
		gen := logProcGen
		logProcMu.Unlock()
		select {
		case <-ch:
			logProcMu.Lock()
			curGen := logProcGen
			logProcMu.Unlock()
			// 同代退出才是真完成；换代（panic 重启）则继续等新一代。
			if curGen == gen {
				return true
			}
		case <-time.After(100 * time.Millisecond):
		}
		if !time.Now().Before(deadline) {
			return false
		}
	}
}

func ProcessLogDequeEngine() {
	logProcMu.Lock()
	logProcGen++
	logProcDoneCh = make(chan struct{})
	logProcMu.Unlock()
	zlog.Info("日志队列处理协程启动")
	defer func() {
		logProcMu.Lock()
		ch := logProcDoneCh
		logProcMu.Unlock()
		close(ch)
	}()

	for {
		select {
		case <-global.GWAF_QUEUE_SHUTDOWN_SIGNAL:
			zlog.Info("日志队列处理协程收到关闭信号，停止接收新批次，开始排空已接收批次...")
			drainLogQueueOnShutdown()
			return
		default:
			global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
			if global.GDATA_CURRENT_CHANGE {
				//如果正在切换库 跳过
				zlog.Debug("正在切换数据库等待中队列")
			} else {
				runLogQueueOnce(false)
			}
			time.Sleep(100 * time.Millisecond)
			global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
		}
	}
}

// runLogQueueOnce 消费一轮。drain=true 为关停排空：取空运行队列、台账忽略退避立即处理。
func runLogQueueOnce(drain bool) {
	webLogArray, otherItems := dequeueRuntimeBatch(drain)
	// 非 WebLog 条目（系统日志、一键任务模型等）维持原行为：立即直写日志库。
	for _, item := range otherItems {
		global.GWAF_LOCAL_LOG_DB.Create(item)
	}

	persistOn := global.GCONFIG_LOG_PERSIST_ENABLED == 1
	ledger := currentLogLedger()
	if ledger == nil && persistOn {
		ledger = ensureLogLedger()
	}

	if len(webLogArray) > 0 {
		zlog.Debug("日志队列处理协程处理日志数量:" + strconv.Itoa(len(webLogArray)))
		if ledger != nil {
			// 可恢复确认路径：接收（冻结分层决策）→ 处理到期批次（补三层/副作用）→ 确认释放。
			ledger.admit(webLogArray)
			negSampler.FlushIfDue()
		} else {
			// 未开启持久化，或台账库打不开：维持改造前的尽力而为路径。
			processWebLogsBestEffort(webLogArray, persistOn)
		}
	}

	// 台账里到期的未确认批次每轮都要推进：故障恢复、重启恢复、开关热关后的遗留收敛都走这里。
	if ledger != nil {
		ledger.processDue(drain)
	}
}

// drainLogQueueOnShutdown 有序关停：不再有新批次从运行队列进入后，反复「排空队列→推进台账」，
// 直到运行队列空且没有未确认批次，或到达等待上限（未确认内容留在台账等下次启动）。
func drainLogQueueOnShutdown() {
	deadline := time.Now().Add(logDrainMaxWait)
	emptyRounds := 0
	for {
		if !global.GDATA_CURRENT_CHANGE {
			runLogQueueOnce(true)
		}
		converged := global.GQEQUE_LOG_DB.Empty()
		if m := currentLogLedger(); m != nil && m.PendingCount() != 0 {
			converged = false
		}
		if converged {
			emptyRounds++
			if emptyRounds >= logDrainEmptyOK {
				zlog.Info("日志队列已排空，已接收批次全部确认释放，日志队列处理协程退出")
				return
			}
		} else {
			emptyRounds = 0
		}
		if !time.Now().Before(deadline) {
			runtimePending := 0
			ledgerPending := int64(0)
			if global.GQEQUE_LOG_DB != nil {
				runtimePending = global.GQEQUE_LOG_DB.Size()
			}
			if m := currentLogLedger(); m != nil {
				ledgerPending = m.PendingCount()
			}
			zlog.Warn("日志队列关停排空超时：未确认批次已保存在本地台账，下次启动继续处理；"+
				"尚在运行队列未落台账的条目可能丢失",
				"pending_in_ledger", ledgerPending, "runtime_queue", runtimePending)
			return
		}
		time.Sleep(logDrainPoll)
	}
}

// dequeueRuntimeBatch 从运行队列取出本轮条目。正常一轮上限 GDATA_BATCH_INSERT+1 条 WebLog
// （与改造前一致）；drain 时取空，WebLog 按批次大小在 admit 内再切块。
func dequeueRuntimeBatch(drain bool) (webLogs []*innerbean.WebLog, others []interface{}) {
	limit := int(global.GDATA_BATCH_INSERT) + 1
	for !global.GQEQUE_LOG_DB.Empty() {
		item, ok := global.GQEQUE_LOG_DB.Dequeue()
		if !ok {
			continue
		}
		global.IncrementLogQPS() // 使用统一的日志QPS增量函数
		if item == nil {
			continue
		}
		if lg, ok := item.(*innerbean.WebLog); ok {
			webLogs = append(webLogs, lg)
			if !drain && len(webLogs) >= limit {
				break
			}
		} else {
			others = append(others, item)
		}
	}
	return webLogs, others
}

// processWebLogsBestEffort 改造前的消费路径，逐字保留：
// IP 失败计数 →（开启持久化时）分层落库+蓄水池刷库 → 流量统计 → 分析统计 → Kafka → 文件日志。
// 各落库/出口失败仍只告警，不影响后续步骤；不开启持久化时不落任何库。
func processWebLogsBestEffort(webLogArray []*innerbean.WebLog, persist bool) {
	// 检查失败状态码并记录IP失败
	logEffectIPFailures(webLogArray)
	if persist {
		// 分层落库：安全事件进 security_event（带报文），窄行进 access_log（按档位），
		// web_logs 不再写入（旧数据只读到期删）。
		storeTiered(webLogArray)
		// 蓄水池采到的正常请求报文攒在内存里，到点整池刷成 event_payload(kind=sample)
		negSampler.FlushIfDue()
	}
	// 日志流做统计
	logEffectTrafficStats(webLogArray)
	// 分析层天级汇总（行为 / 目标 / 手法三视角）
	logEffectAnalysisStats(webLogArray)
	logEffectKafkaBatch(webLogArray)
	logEffectFileBatch(webLogArray)
}

// 副作用钩子（包级变量，单测可替换计数）。台账路径与旧路径共用同一组实现，
// 保证两条路径对 IP 失败/统计/Kafka/文件的行为一致。
var (
	// logEffectIPFailures 失败状态码 → IP 失败计数（封禁判定窗口用）。
	logEffectIPFailures = func(logs []*innerbean.WebLog) {
		if global.GCONFIG_IP_FAILURE_BAN_ENABLED != 1 {
			return
		}
		ipManager := wafipban.GetIPFailureManager()
		for _, lg := range logs {
			if lg != nil && ipManager.IsFailureStatusCode(lg.STATUS_CODE) {
				ipManager.RecordFailure(lg)
			}
		}
	}
	// logEffectTrafficStats 主机/IP/城市/站点的天级与小时聚合。
	logEffectTrafficStats = waftask.CollectStatsFromLogs
	// logEffectAnalysisStats 分析层三视角天级汇总（键必须与窄行同源，见 log_keys.go）。
	logEffectAnalysisStats = func(logs []*innerbean.WebLog) {
		waftask.CollectAnalysisStats(AnalysisRowsFromLogs(logs))
	}
	// logEffectKafkaBatch Kafka 批量外发（未初始化/未启用时服务自身短路）。
	logEffectKafkaBatch = func(logs []*innerbean.WebLog) {
		if global.GNOTIFY_KAKFA_SERVICE != nil {
			_ = global.GNOTIFY_KAKFA_SERVICE.ProcessBatchLogs(logs)
		}
	}
	// logEffectFileBatch 文件日志批量写入。
	logEffectFileBatch = func(logs []*innerbean.WebLog) {
		if global.GNOTIFY_LOG_FILE_WRITER != nil {
			_ = global.GNOTIFY_LOG_FILE_WRITER.ProcessBatchLogs(logs)
		}
	}
)

// processClassifiedBestEffort 台账接收失败（序列化失败/台账库不可写）时的退路：
// 用接收时已分好的三层行（不再二次进蓄水池采样），严格按改造前顺序收尾：
// IP 失败计数 → 三层落库（各自只告警）→ 蓄水池刷库 → 流量统计 → 分析 → Kafka → 文件。
func processClassifiedBestEffort(logs []*innerbean.WebLog, events []*model.SecurityEvent, accesses []*model.AccessLog, payloads []*model.EventPayload) {
	logEffectIPFailures(logs)
	storeTieredRowsBestEffort(events, accesses, payloads)
	negSampler.FlushIfDue()
	logEffectTrafficStats(logs)
	logEffectAnalysisStats(logs)
	logEffectKafkaBatch(logs)
	logEffectFileBatch(logs)
}
