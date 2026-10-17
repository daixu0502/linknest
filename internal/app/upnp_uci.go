package app

// Stock UCI can leave custom -P deltas unmerged even after a successful commit.
// Export the staged view explicitly, validate it without those deltas, then use
// that materialized file for the existing atomic install/rollback transaction.
func upnpMaterializeUCI(pkg string) string {
	if pkg != "upnpd" && pkg != "firewall" {
		panic("unsupported native UCI package")
	}
	return `uci -c "$work" -P "$work/delta" export ` + pkg + ` >"$work/staged-export"
sed '/^package /d' "$work/staged-export" >"$work/rendered"
[ -s "$work/rendered" ] || { echo '原厂配置生成结果为空，未修改' >&2; exit 1; }
mkdir "$work/verify" "$work/verify/delta"
cp "$work/rendered" "$work/verify/` + pkg + `"
uci -c "$work/verify" -P "$work/verify/delta" export ` + pkg + ` >"$work/verified-export"
cmp -s "$work/staged-export" "$work/verified-export" || { echo '原厂配置独立校验不一致，未修改' >&2; exit 1; }
cp "$work/rendered" "$work/` + pkg + `"
`
}
