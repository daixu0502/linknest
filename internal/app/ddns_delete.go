package app

import (
	"context"
	"net/http"
	"time"
)

func (a *App) deleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ID           string `json:"id"`
		RecordID     string `json:"recordId"`
		DeleteRemote bool   `json:"deleteRemote"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	before := a.store.snapshot()
	taskIndex, recordIndex := -1, -1
	for i, task := range before.DDNS {
		if task.ID != q.ID {
			continue
		}
		taskIndex = i
		for j, rec := range task.Records {
			if rec.ID == q.RecordID {
				recordIndex = j
				break
			}
		}
	}
	if taskIndex < 0 || recordIndex < 0 {
		fail(w, 404, "解析记录不存在")
		return
	}
	if !a.dns.reserveDelete(q.ID) {
		fail(w, 409, "此任务正在同步，请等待同步结束后再删除")
		return
	}
	defer a.dns.releaseDelete(q.ID)
	rec := before.DDNS[taskIndex].Records[recordIndex]
	message := "已删除本地配置，保留远端 DNS 记录"
	if q.DeleteRemote {
		// Two local entries must not unknowingly delete each other's remote record.
		for _, task := range before.DDNS {
			for _, other := range task.Records {
				if other.ID != rec.ID && other.Domain == rec.Domain && other.Type == rec.Type && other.Line == rec.Line {
					fail(w, 409, "另一条本地配置也引用了同名、同类型、同线路记录；请先核对，或仅删除本地配置")
					return
				}
			}
		}
		account, err := a.store.dnsAccount(q.ID)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		deleted, err := a.dns.client(account).deleteRecord(ctx, rec)
		if err != nil {
			fail(w, 502, "未完成远端删除，本地配置保留："+err.Error())
			return
		}
		message = "远端记录已不存在，已删除本地配置"
		if deleted {
			message = "已删除远端 DNS 记录和本地配置"
		}
	}
	after := a.store.snapshot()
	records := after.DDNS[taskIndex].Records
	after.DDNS[taskIndex].Records = append(records[:recordIndex], records[recordIndex+1:]...)
	if err := a.store.save(after); err != nil {
		fail(w, 500, "本地配置保存失败（远端操作可能已完成），请核对后重试："+err.Error())
		return
	}
	a.dns.releaseDelete(q.ID)
	a.dns.configChanged(before, a.store.snapshot())
	a.event("info", rec.Domain+"："+message)
	respond(w, 200, map[string]any{"ok": true, "message": message})
}
