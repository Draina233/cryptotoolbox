"""统一结果模型：所有页面最终都渲染为 Report。

状态语义：
- pass    ：已验证通过（密码学验签通过 / 格式校验通过）
- fail    ：明确失败
- unknown ：无法判定（算法不支持、缺少信任锚、需要人工复核）——绝不能显示为 pass
- skip    ：不适用
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from typing import Any, Iterable

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
SKIP = "skip"

STATUS_LABELS = {
    PASS: "通过",
    FAIL: "未通过",
    UNKNOWN: "未知",
    SKIP: "不适用",
}

STATUS_COLORS = {
    PASS: "#15803D",
    FAIL: "#B91C1C",
    UNKNOWN: "#64748B",
    SKIP: "#94A3B8",
}


@dataclass
class CheckResult:
    key: str
    label: str
    status: str = UNKNOWN
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def label_text(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


@dataclass
class Report:
    title: str
    rows: list[CheckResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    full_raw: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------ 构建
    def add(self, key: str, label: str, status: str = UNKNOWN, detail: str = "", **extra) -> CheckResult:
        row = CheckResult(key=key, label=label, status=status, detail=detail, extra=extra)
        self.rows.append(row)
        return row

    def note(self, text: str) -> None:
        self.notes.append(text)

    def counts(self) -> dict[str, int]:
        result = {PASS: 0, FAIL: 0, UNKNOWN: 0, SKIP: 0}
        for row in self.rows:
            result[row.status] = result.get(row.status, 0) + 1
        return result

    def verdict(self) -> str:
        """整体结论：有明确失败 → fail；全部通过 → pass；否则 unknown。"""
        counts = self.counts()
        if counts.get(FAIL):
            return FAIL
        if counts.get(UNKNOWN):
            return UNKNOWN
        # 只有 SKIP（例如 detached 签名未提供原文）不算通过，避免误导
        if counts.get(SKIP):
            return UNKNOWN
        return PASS if counts.get(PASS) else UNKNOWN

    # ------------------------------------------------------------ 序列化
    def to_text(self, include_full: bool = True) -> str:
        lines = [f"{self.title}", "=" * min(60, max(20, len(self.title) * 2))]
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"生成时间：{stamp}")
        for key, value in self.meta.items():
            lines.append(f"{key}：{_flatten(value)}")
        lines.append("")
        for row in self.rows:
            lines.append(f"[{row.label_text()}] {row.label}" + (f" —— {row.detail}" if row.detail else ""))
            for k, v in row.extra.items():
                lines.append(f"    {k}: {_flatten(v)}")
        if self.notes:
            lines.append("")
            lines.append("说明：")
            for note in self.notes:
                lines.append(f"- {note}")
        for key, value in self.raw.items():
            lines.append("")
            lines.append(f"--- {key} ---")
            lines.append(_flatten(value))
        if include_full:
            full = self._full_raw_text()
            if full:
                lines.append(full)
        return "\n".join(lines)

    def to_display_text(self, max_chars: int = 30_000) -> str:
        """界面显示用文本：不含完整签名数据，并限制总长度，避免超大报告卡死 UI。"""
        text = self.to_text(include_full=False)
        if len(text) > max_chars:
            text = text[:max_chars] + (
                f"\n\n…（界面仅显示前 {max_chars} 字符；完整签名数据请使用“导出报告”查看）"
            )
        return text + "\n"

    def _full_raw_text(self) -> str:
        if not self.full_raw:
            return ""
        lines = ["", "完整签名数据（未截断）"]
        for key, value in self.full_raw.items():
            lines.append(f"{key}（{len(value) // 2} 字节）:")
            lines.append(value)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "meta": self.meta,
            "rows": [
                {
                    "key": r.key,
                    "label": r.label,
                    "status": r.status,
                    "status_text": r.label_text(),
                    "detail": r.detail,
                    "extra": r.extra,
                }
                for r in self.rows
            ],
            "notes": self.notes,
            "raw": {k: _jsonable(v) for k, v in self.raw.items()},
            "full_raw": dict(self.full_raw),
            "counts": self.counts(),
            "verdict": self.verdict(),
        }

    def to_html(self) -> str:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows_html = []
        for row in self.rows:
            color = STATUS_COLORS.get(row.status, "#64748B")
            extra = "".join(
                f'<div class="extra">{escape(str(k))}: {escape(_flatten(v))}</div>' for k, v in row.extra.items()
            )
            rows_html.append(
                "<tr>"
                f'<td class="label">{escape(row.label)}</td>'
                f'<td class="status" style="color:{color}">{escape(row.label_text())}</td>'
                f'<td class="detail">{escape(row.detail)}{extra}</td>'
                "</tr>"
            )
        notes_html = "".join(f"<li>{escape(n)}</li>" for n in self.notes)
        meta_html = "".join(f"<li>{escape(str(k))}：{escape(_flatten(v))}</li>" for k, v in self.meta.items())
        raw_html = "".join(
            f'<h3>{escape(str(k))}</h3><pre>{escape(_flatten(v))}</pre>' for k, v in self.raw.items()
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"/>
<title>{escape(self.title)}</title>
<style>
body {{ font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif; color:#14283F; margin:32px; background:#F5F7FA; }}
h1 {{ font-size:22px; margin-bottom:4px; }}
.meta {{ color:#5A6B80; font-size:13px; margin-bottom:18px; }}
table {{ border-collapse:collapse; width:100%; background:#fff; border:1px solid #DFE7F1; border-radius:8px; overflow:hidden; }}
th {{ background:#F2F6FB; text-align:left; padding:8px 10px; font-size:13px; color:#5A6B80; border-bottom:1px solid #DFE7F1; }}
td {{ padding:8px 10px; border-bottom:1px solid #EEF2F8; font-size:13px; vertical-align:top; }}
td.label {{ width:220px; font-weight:600; }}
td.status {{ width:80px; white-space:nowrap; }}
.extra {{ color:#5A6B80; font-size:12px; margin-top:2px; }}
.note {{ margin-top:18px; color:#5A6B80; font-size:12px; }}
pre {{ background:#fff; border:1px solid #DFE7F1; border-radius:8px; padding:10px; font-size:12px; overflow:auto; }}
</style></head><body>
<h1>{escape(self.title)}</h1>
<div class="meta">生成时间：{stamp}</div>
<ul class="meta">{meta_html}</ul>
<table><thead><tr><th>检测项</th><th>结果</th><th>说明</th></tr></thead><tbody>{''.join(rows_html)}</tbody></table>
{('<div class="note"><b>说明</b><ul>' + notes_html + "</ul></div>") if notes_html else ""}
{raw_html}
{(('<h2>完整签名数据（未截断）</h2>' + ''.join(f"<pre>{escape(k)}（{len(v) // 2} 字节）\n{escape(v)}</pre>" for k, v in self.full_raw.items())) if self.full_raw else "")}
</body></html>"""


def _flatten(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        text = data.hex().upper()
        return text if len(text) <= 256 else text[:256] + f"…（共 {len(data)} 字节）"
    if isinstance(value, (list, tuple)):
        return " / ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(_jsonable(value), ensure_ascii=False, indent=2)
    return str(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def export_report(report: Report, path: str) -> None:
    """按扩展名导出 JSON / TXT / HTML。"""
    lower = path.lower()
    if lower.endswith(".json"):
        text = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    elif lower.endswith(".html") or lower.endswith(".htm"):
        text = report.to_html()
    else:
        text = report.to_text()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
