import React from "react";
import * as ReactDOM from "react-dom/client";
import * as antd from "antd";
import { CopyOutlined, DownloadOutlined, PlusOutlined, SettingOutlined } from "@ant-design/icons";
import "antd/dist/reset.css";
import "./style.css";

const { useEffect, useMemo, useRef, useState } = React;
const {
  Layout, Typography, Card, Space, Button, Table, Tag, Form, Input, InputNumber, Switch, Checkbox,
  Modal, Tabs, message, Popconfirm, Alert, Divider, Tooltip, Select, Descriptions,
} = antd;

const WEB_AUTH_STORAGE_KEY = "anytls_web_auth_v1";
const WEB_AUTH_SESSION_KEY = "anytls_web_auth_session_v1";
const PROBE_RESULT_STORAGE_PREFIX = "anytls_probe_results_v1";
const DEFAULT_API_TIMEOUT_MS = 15000;
const TUN_TOGGLE_REQUEST_TIMEOUT_MS = 8000;
const TUN_TOGGLE_POLL_INTERVAL_MS = 1000;
const TUN_TOGGLE_TASK_TIMEOUT_MS = 150000;
const DEFAULT_EGRESS_PROBE_TARGET = "https://www.google.com/generate_204";

function parseAuthRecord(raw) {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return null;
    }
    const username = typeof parsed.username === "string" ? parsed.username.trim() : "";
    const password = typeof parsed.password === "string" ? parsed.password : "";
    if (!username || !password) {
      return null;
    }
    return {username, password};
  } catch {
    return null;
  }
}

function loadSavedAuth() {
  if (typeof window === "undefined") {
    return null;
  }
  return parseAuthRecord(window.localStorage.getItem(WEB_AUTH_STORAGE_KEY))
    || parseAuthRecord(window.sessionStorage.getItem(WEB_AUTH_SESSION_KEY));
}

function saveAuth(username, password, remember) {
  if (typeof window === "undefined") {
    return;
  }
  const value = JSON.stringify({username, password});
  if (remember) {
    window.localStorage.setItem(WEB_AUTH_STORAGE_KEY, value);
    window.sessionStorage.removeItem(WEB_AUTH_SESSION_KEY);
    return;
  }
  window.sessionStorage.setItem(WEB_AUTH_SESSION_KEY, value);
  window.localStorage.removeItem(WEB_AUTH_STORAGE_KEY);
}

function clearSavedAuth() {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.removeItem(WEB_AUTH_STORAGE_KEY);
  window.sessionStorage.removeItem(WEB_AUTH_SESSION_KEY);
}

function buildProbeResultStorageKey(configPath) {
  const path = String(configPath || "").trim();
  return `${PROBE_RESULT_STORAGE_PREFIX}::${path || "default"}`;
}

function normalizeProbeResultMap(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }
  const out = {};
  Object.entries(input).forEach(([rawKey, rawValue]) => {
    const key = String(rawKey || "").trim();
    if (!key) {
      return;
    }
    const value = String(rawValue == null ? "" : rawValue).trim();
    if (!value) {
      return;
    }
    out[key] = value;
  });
  return out;
}

function loadProbeResultStateByKey(storageKey) {
  if (typeof window === "undefined" || !storageKey) {
    return {latency: {}, bandwidth: {}};
  }
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) {
      return {latency: {}, bandwidth: {}};
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return {latency: {}, bandwidth: {}};
    }
    return {
      latency: normalizeProbeResultMap(parsed.latency),
      bandwidth: normalizeProbeResultMap(parsed.bandwidth),
    };
  } catch {
    return {latency: {}, bandwidth: {}};
  }
}

function saveProbeResultStateByKey(storageKey, latencyResult, bandwidthResult) {
  if (typeof window === "undefined" || !storageKey) {
    return;
  }
  const payload = {
    latency: normalizeProbeResultMap(latencyResult),
    bandwidth: normalizeProbeResultMap(bandwidthResult),
  };
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(payload));
  } catch {
    // ignore quota/security errors
  }
}

function formatPercent(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) {
    return "0.0%";
  }
  return `${n.toFixed(1)}%`;
}

function shortCommit(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "unknown") {
    return "-";
  }
  return raw.length > 12 ? raw.slice(0, 12) : raw;
}

const CST_TIME_ZONE = "Asia/Shanghai";
const cstDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  timeZone: CST_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function parseDateInput(raw) {
  const value = String(raw || "").trim();
  if (!value || value === "-" || value === "unknown") {
    return null;
  }
  let normalized = value;
  // Legacy values without timezone are treated as UTC to avoid host timezone drift.
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = `${normalized.replace(" ", "T")}Z`;
  } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date;
}

function formatDateTimeCST(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "unknown") {
    return "-";
  }
  const date = parseDateInput(raw);
  if (!date) {
    return raw;
  }
  const partMap = {};
  cstDateTimeFormatter.formatToParts(date).forEach((part) => {
    if (part.type !== "literal") {
      partMap[part.type] = part.value;
    }
  });
  return `${partMap.year}-${partMap.month}-${partMap.day} ${partMap.hour}:${partMap.minute}:${partMap.second}`;
}

function formatBuildTime(value) {
  return formatDateTimeCST(value);
}

function toPositiveInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    return 0;
  }
  return Math.floor(n);
}

function formatSecondsCN(totalSeconds) {
  const sec = toPositiveInt(totalSeconds);
  if (!sec) {
    return "-";
  }
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) {
    return `${h}小时${m}分${s}秒`;
  }
  if (m > 0) {
    return `${m}分${s}秒`;
  }
  return `${s}秒`;
}

function formatTaskQueueSummary(task) {
  const pos = toPositiveInt(task?.queue_position);
  if (!pos) {
    return "-";
  }
  const total = toPositiveInt(task?.queue_total) || pos;
  const eta = toPositiveInt(task?.queue_eta_seconds);
  const parts = [`第 ${pos}/${total} 位`];
  if (eta > 0) {
    parts.push(`预计剩余 ${formatSecondsCN(eta)}`);
  }
  return parts.join(" · ");
}

function formatTaskElapsedSummary(task) {
  const elapsed = toPositiveInt(task?.elapsed_seconds);
  if (!elapsed) {
    return "";
  }
  return `已耗时 ${formatSecondsCN(elapsed)}`;
}

function formatSubscriptionParseSummary(summary) {
  if (!summary || typeof summary !== "object") {
    return "-";
  }
  const parts = [];
  const skippedUnsupported = toPositiveInt(summary.skipped_unsupported);
  const skippedInvalid = toPositiveInt(summary.skipped_invalid);
  const partialMapped = toPositiveInt(summary.partial_mapped);
  const ignoredFieldCount = toPositiveInt(summary.ignored_field_count);
  if (skippedUnsupported > 0) {
    parts.push(`跳过协议 ${skippedUnsupported}`);
  }
  if (skippedInvalid > 0) {
    parts.push(`无效 ${skippedInvalid}`);
  }
  if (partialMapped > 0) {
    parts.push(`部分映射 ${partialMapped}`);
  }
  if (ignoredFieldCount > 0) {
    parts.push(`忽略字段 ${ignoredFieldCount}`);
  }
  const top = Array.isArray(summary.ignored_field_top) ? summary.ignored_field_top : [];
  if (top.length > 0) {
    const topText = top
      .slice(0, 3)
      .map((item) => `${item?.field || "?"}(${toPositiveInt(item?.count)})`)
      .join(", ");
    if (topText) {
      parts.push(`Top: ${topText}`);
    }
  }
  return parts.join(" ; ") || "-";
}

function buildTaskProgressDescription(task, nowMS = Date.now()) {
  if (!task) {
    return "-";
  }
  const now = toPositiveInt(nowMS);
  const enqueueAt = toPositiveInt(task._enqueued_at_ms);
  const waitedSeconds = enqueueAt > 0 && now > enqueueAt
    ? Math.floor((now - enqueueAt) / 1000)
    : 0;
  let etaSeconds = toPositiveInt(task?.queue_eta_seconds);
  if (!etaSeconds) {
    const fallbackETA = toPositiveInt(task?._fallback_eta_seconds);
    if (fallbackETA > 0) {
      etaSeconds = Math.max(fallbackETA - waitedSeconds, 0);
    }
  }
  const parts = [];
  const detail = String(task.error || task.message || "").trim();
  if (detail) {
    parts.push(detail);
  }
  const queuePos = toPositiveInt(task?.queue_position);
  if (queuePos > 0) {
    const queue = formatTaskQueueSummary({
      queue_position: queuePos,
      queue_total: toPositiveInt(task?.queue_total),
      queue_eta_seconds: etaSeconds,
    });
    if (queue !== "-") {
      parts.push(queue);
    }
  } else if (etaSeconds > 0) {
    parts.push(`预计剩余 ${formatSecondsCN(etaSeconds)}`);
  }
  const elapsed = formatTaskElapsedSummary(task);
  if (elapsed) {
    parts.push(elapsed);
  }
  if (!elapsed && waitedSeconds > 0) {
    parts.push(`已等待 ${formatSecondsCN(waitedSeconds)}`);
  }
  return parts.join(" | ") || "-";
}

function extractTunMismatchRows(tunCheckRaw) {
  const extras = tunCheckRaw?.extras || {};
  const probeRows = []
    .concat(Array.isArray(extras?.https_probe?.results) ? extras.https_probe.results : [])
    .concat(Array.isArray(extras?.system_https_probe?.results) ? extras.system_https_probe.results : []);
  const rows = [];
  probeRows.forEach((item, index) => {
    if (String(item?.error_type || "").trim() !== "hostname_mismatch") {
      return;
    }
    const host = String(item?.host || "").trim() || (String(item?.url || "").replace(/^https?:\/\//, "").split("/")[0] || "-");
    const dnsNames = Array.isArray(item?.cert_dns_names) ? item.cert_dns_names : [];
    rows.push({
      key: `${host}-${index}`,
      host,
      url: String(item?.url || "").trim(),
      cert_subject: String(item?.cert_subject || "").trim() || "-",
      cert_dns_names: dnsNames.length ? dnsNames.join(", ") : "-",
      error: String(item?.error || "").trim() || "-",
      duration_ms: toPositiveInt(item?.duration_ms),
    });
  });
  return rows;
}

function extractTunDNSProbeRows(tunCheckRaw) {
  const rows = Array.isArray(tunCheckRaw?.extras?.dns_resolution_probe?.results)
    ? tunCheckRaw.extras.dns_resolution_probe.results
    : [];
  return rows.map((item, index) => ({
    key: `${item?.host || "host"}-${item?.dns_server || "dns"}-${index}`,
    host: String(item?.host || "").trim() || "-",
    dns_server: String(item?.dns_server || "").trim() || "-",
    network: String(item?.network || "").trim() || "-",
    ips: Array.isArray(item?.ips) ? item.ips.join(", ") : "-",
    ok: !!item?.ok,
    error: String(item?.error || "").trim(),
    duration_ms: toPositiveInt(item?.duration_ms),
  }));
}

function shortTaskID(id) {
  const raw = String(id || "").trim();
  if (!raw) {
    return "-";
  }
  if (raw.length <= 28) {
    return raw;
  }
  return `${raw.slice(0, 12)}...${raw.slice(-8)}`;
}

function buildTaskQueueOverviewText(queue) {
  if (!queue || typeof queue !== "object") {
    return "队列信息不可用";
  }
  const parts = [];
  const total = toPositiveInt(queue.total);
  const pending = toPositiveInt(queue.pending);
  if (total > 0) {
    parts.push(`总任务 ${total}`);
  }
  if (pending > 0) {
    parts.push(`排队 ${pending}`);
  }
  if (queue.running) {
    const runningKind = String(queue.running_kind || "tun_toggle").trim();
    const runningID = shortTaskID(queue.running_task_id);
    parts.push(`执行中 ${runningKind} (${runningID})`);
    const eta = toPositiveInt(queue.running_eta_seconds);
    if (eta > 0) {
      parts.push(`预计剩余 ${formatSecondsCN(eta)}`);
    }
  }
  const wait = toPositiveInt(queue.oldest_pending_wait_seconds);
  if (wait > 0) {
    parts.push(`最久等待 ${formatSecondsCN(wait)}`);
  }
  return parts.join(" | ") || "队列为空";
}

function formatClockTime(input) {
  const n = Number(input);
  if (!Number.isFinite(n) || n <= 0) {
    return "--:--:--";
  }
  const d = new Date(n);
  const pad = (v) => String(v).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function appendTunStepLog(logs, text, atMS = Date.now()) {
  const msg = String(text || "").trim();
  if (!msg) {
    return Array.isArray(logs) ? logs : [];
  }
  const arr = Array.isArray(logs) ? [...logs] : [];
  const last = arr.length > 0 ? arr[arr.length - 1] : null;
  if (last && String(last.text || "").trim() === msg) {
    return arr;
  }
  arr.push({
    at: Number(atMS) > 0 ? Number(atMS) : Date.now(),
    text: msg,
  });
  if (arr.length > 40) {
    return arr.slice(arr.length - 40);
  }
  return arr;
}

function toBasicAuth(username, password) {
  const plain = `${username}:${password}`;
  try {
    return `Basic ${window.btoa(unescape(encodeURIComponent(plain)))}`;
  } catch {
    return `Basic ${window.btoa(plain)}`;
  }
}

function shellQuoteSingle(input) {
  const raw = String(input == null ? "" : input);
  return `'${raw.replace(/'/g, `'\"'\"'`)}'`;
}

async function copyTextToClipboard(text) {
  const value = String(text == null ? "" : text);
  if (!value) {
    throw new Error("复制内容为空");
  }
  if (typeof navigator !== "undefined" && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    await navigator.clipboard.writeText(value);
    return;
  }
  if (typeof document === "undefined") {
    throw new Error("当前环境不支持复制");
  }
  const el = document.createElement("textarea");
  el.value = value;
  el.setAttribute("readonly", "");
  el.style.position = "fixed";
  el.style.left = "-9999px";
  document.body.appendChild(el);
  el.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(el);
  if (!ok) {
    throw new Error("复制失败，请手动复制");
  }
}

async function api(path, options = {}) {
  const {suppressAuthEvent, timeoutMS, ...fetchOptions} = options;
  const effectiveTimeoutMS = Number.isFinite(timeoutMS) && timeoutMS > 0 ? timeoutMS : DEFAULT_API_TIMEOUT_MS;
  const saved = loadSavedAuth();
  const headers = {"Content-Type": "application/json", ...(fetchOptions.headers || {})};
  if (!headers.Authorization && saved) {
    headers.Authorization = toBasicAuth(saved.username, saved.password);
  }

  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => {
    controller.abort();
  }, effectiveTimeoutMS);

  let res;
  try {
    res = await fetch(path, {
      headers,
      ...fetchOptions,
      signal: controller.signal
    });
  } catch (err) {
    if (err && err.name === "AbortError") {
      throw new Error(`请求超时（${effectiveTimeoutMS}ms）`);
    }
    throw err;
  } finally {
    window.clearTimeout(timeoutId);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    if (res.status === 401 && !suppressAuthEvent && typeof window !== "undefined") {
      window.dispatchEvent(new Event("anytls-auth-unauthorized"));
    }
    throw err;
  }
  return data;
}

function waitMS(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

async function waitTaskDone(taskID, options = {}) {
  const {timeoutMS = TUN_TOGGLE_TASK_TIMEOUT_MS, onProgress} = options;
  const id = String(taskID || "").trim();
  if (!id) {
    throw new Error("task id is empty");
  }
  const startedAt = Date.now();
  let notFoundStreak = 0;
  let lastTask = null;
  while (Date.now() - startedAt < timeoutMS) {
    try {
      const task = await api(`/api/v1/tasks/${encodeURIComponent(id)}`, {
        timeoutMS: 5000,
      });
      lastTask = task && typeof task === "object" ? task : lastTask;
      notFoundStreak = 0;
      if (typeof onProgress === "function") {
        onProgress(task);
      }
      const status = String(task?.status || "").toLowerCase();
      if (status === "success") {
        return task;
      }
      if (status === "failed") {
        const err = new Error(task?.error || task?.message || "任务执行失败");
        err.task = task;
        throw err;
      }
    } catch (err) {
      const statusCode = Number(err?.status || 0);
      const msg = String(err?.message || "");
      if (statusCode === 404 || msg.includes("task not found")) {
        notFoundStreak += 1;
        if (notFoundStreak >= 6) {
          throw new Error("任务不存在或已被回收，请重试");
        }
      } else {
        notFoundStreak = 0;
      }
      const transient = statusCode === 0
        || statusCode === 404
        || msg.includes("task not found")
        || msg.includes("请求超时")
        || msg.includes("Failed to fetch")
        || msg.includes("NetworkError");
      if (!transient) {
        if (!err?.task && lastTask) {
          err.task = lastTask;
        }
        throw err;
      }
    }
    await waitMS(TUN_TOGGLE_POLL_INTERVAL_MS);
  }
  try {
    const task = await api(`/api/v1/tasks/${encodeURIComponent(id)}`, {
      timeoutMS: 15000,
    });
    if (typeof onProgress === "function") {
      onProgress(task);
    }
    const status = String(task?.status || "").toLowerCase();
    if (status === "success") {
      return task;
    }
    if (status === "failed") {
      const err = new Error(task?.error || task?.message || "任务执行失败");
      err.task = task;
      throw err;
    }
    const detail = String(task?.message || "").trim();
    const err = new Error(detail ? `请求超时（${timeoutMS}ms），当前阶段: ${detail}` : `请求超时（${timeoutMS}ms）`);
    err.task = task;
    throw err;
  } catch (err) {
    if (err?.task) {
      throw err;
    }
    const timeoutErr = new Error(`请求超时（${timeoutMS}ms）`);
    if (lastTask) {
      timeoutErr.task = lastTask;
    }
    throw timeoutErr;
  }
}

async function createAsyncTask(kind, payload = {}) {
  const req = {kind: String(kind || "").trim(), ...(payload || {})};
  const res = await api("/api/v1/tasks", {
    method: "POST",
    body: JSON.stringify(req),
    timeoutMS: DEFAULT_API_TIMEOUT_MS,
  });
  const taskID = String(res?.task_id || "").trim();
  if (!taskID) {
    throw new Error("创建任务失败：未返回 task_id");
  }
  return taskID;
}

const ROUTING_RULE_TYPE_OPTIONS = [
  {value: "DOMAIN", label: "DOMAIN 精确域名"},
  {value: "DOMAIN-SUFFIX", label: "DOMAIN-SUFFIX 域名后缀"},
  {value: "DOMAIN-KEYWORD", label: "DOMAIN-KEYWORD 域名关键词"},
  {value: "DOMAIN-REGEX", label: "DOMAIN-REGEX 正则域名"},
  {value: "IP-CIDR", label: "IP-CIDR IPv4 网段"},
  {value: "IP-CIDR6", label: "IP-CIDR6 IPv6 网段"},
  {value: "GEOIP", label: "GEOIP 国家码"},
  {value: "DST-PORT", label: "DST-PORT 目标端口"},
  {value: "RULE-SET", label: "RULE-SET 规则集引用"},
  {value: "MATCH", label: "MATCH 全匹配"},
  {value: "AND", label: "AND 组合条件"},
  {value: "OR", label: "OR 任一条件"},
  {value: "NOT", label: "NOT 取反条件"},
  {value: "ADVANCED", label: "高级(手写)"},
];

const ROUTING_RULE_SIMPLE_TYPES = new Set([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-REGEX",
  "IP-CIDR",
  "IP-CIDR6",
  "GEOIP",
  "DST-PORT",
  "RULE-SET",
  "MATCH",
]);

const ROUTING_RULE_LOGICAL_TYPES = new Set(["AND", "OR", "NOT"]);

const ROUTING_LOGICAL_CHILD_TYPE_OPTIONS = [
  {value: "DOMAIN", label: "DOMAIN 精确域名"},
  {value: "DOMAIN-SUFFIX", label: "DOMAIN-SUFFIX 域名后缀"},
  {value: "DOMAIN-KEYWORD", label: "DOMAIN-KEYWORD 域名关键词"},
  {value: "DOMAIN-REGEX", label: "DOMAIN-REGEX 正则域名"},
  {value: "IP-CIDR", label: "IP-CIDR IPv4 网段"},
  {value: "IP-CIDR6", label: "IP-CIDR6 IPv6 网段"},
  {value: "GEOIP", label: "GEOIP 国家码"},
  {value: "DST-PORT", label: "DST-PORT 目标端口"},
  {value: "RULE-SET", label: "RULE-SET 规则集引用"},
  {value: "MATCH", label: "MATCH 全匹配"},
  {value: "ADVANCED", label: "子条件高级手写"},
];

function hasWrappingParentheses(input) {
  const s = String(input || "").trim();
  if (s.length < 2 || s[0] !== "(" || s[s.length - 1] !== ")") {
    return false;
  }
  let depth = 0;
  let quote = "";
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) {
        quote = "";
      }
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (ch === "(") {
      depth += 1;
      continue;
    }
    if (ch === ")") {
      depth -= 1;
      if (depth === 0 && i !== s.length - 1) {
        return false;
      }
      if (depth < 0) {
        return false;
      }
    }
  }
  return depth === 0;
}

function unwrapOuterParentheses(input) {
  let s = String(input || "").trim();
  while (hasWrappingParentheses(s)) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function splitRuleCSVLine(line) {
  const input = String(line || "").trim();
  if (!input) {
    return [];
  }
  const parts = [];
  let token = "";
  let depth = 0;
  let quote = "";
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      token += ch;
      if (ch === quote) {
        quote = "";
      }
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      token += ch;
      continue;
    }
    if (ch === "(") {
      depth += 1;
      token += ch;
      continue;
    }
    if (ch === ")") {
      depth = Math.max(0, depth - 1);
      token += ch;
      continue;
    }
    if (ch === "," && depth === 0) {
      const part = token.trim();
      if (part) {
        parts.push(part);
      }
      token = "";
      continue;
    }
    token += ch;
  }
  const tail = token.trim();
  if (tail) {
    parts.push(tail);
  }
  return parts;
}

function parseRuleAction(raw) {
  const token = String(raw || "").trim();
  if (!token) {
    return {action_kind: "group", action_node: "", action_group: ""};
  }
  if (token.toUpperCase().startsWith("GROUP:")) {
    return {
      action_kind: "group",
      action_node: "",
      action_group: String(token.slice("GROUP:".length)).trim(),
    };
  }
  switch (token.toUpperCase()) {
    case "DIRECT":
      return {action_kind: "direct", action_node: "", action_group: ""};
    case "REJECT":
    case "REJECT-DROP":
      return {action_kind: "reject", action_node: "", action_group: ""};
    case "PROXY":
      return {action_kind: "proxy", action_node: "", action_group: ""};
    default:
      return {action_kind: "node", action_node: token, action_group: ""};
  }
}

function buildRuleAction(actionKind, actionNode, actionGroup) {
  switch (String(actionKind || "").trim().toLowerCase()) {
    case "direct":
      return "DIRECT";
    case "reject":
      return "REJECT";
    case "proxy":
      return "PROXY";
    case "group": {
      const group = String(actionGroup || "").trim();
      if (!group) {
        throw new Error("请选择目标分组");
      }
      return `GROUP:${group}`;
    }
    case "node": {
      const node = String(actionNode || "").trim();
      if (!node) {
        throw new Error("请选择目标节点");
      }
      return node;
    }
    default:
      throw new Error("动作无效");
  }
}

function pickPreferredRoutingGroup(groups) {
  const list = (Array.isArray(groups) ? groups : [])
    .map((x) => String(x || "").trim())
    .filter(Boolean);
  if (list.length === 0) {
    return "";
  }
  if (list.includes("节点选择")) {
    return "节点选择";
  }
  return list[0];
}

function parseRoutingDefaultActionToForm(raw) {
  const parsed = parseRuleAction(raw);
  if (parsed.action_kind === "group") {
    return {kind: "group", group: String(parsed.action_group || "").trim()};
  }
  if (parsed.action_kind === "direct") {
    return {kind: "direct", group: ""};
  }
  if (parsed.action_kind === "reject") {
    return {kind: "reject", group: ""};
  }
  // Legacy/unknown values (e.g. PROXY) fallback to group mode.
  return {kind: "group", group: ""};
}

function buildRoutingDefaultActionFromForm(actionKind, actionGroup) {
  const kind = String(actionKind || "").trim().toLowerCase();
  switch (kind) {
    case "direct":
      return "DIRECT";
    case "reject":
      return "REJECT";
    case "group": {
      const group = String(actionGroup || "").trim();
      if (!group) {
        throw new Error("请选择默认兜底分组");
      }
      return `GROUP:${group}`;
    }
    default:
      throw new Error("请选择默认兜底动作");
  }
}

function parseRoutingGeoIPToForm(raw) {
  const cfg = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  if (!cfg) {
    return {
      enabled: false,
      type: "http",
      url: "",
      path: "",
      interval_sec: 3600,
    };
  }
  const typeRaw = String(cfg.type || "").trim().toLowerCase();
  const type = typeRaw === "file" ? "file" : "http";
  const interval = Number(cfg.interval_sec);
  return {
    enabled: true,
    type,
    url: String(cfg.url || "").trim(),
    path: String(cfg.path || "").trim(),
    interval_sec: Number.isFinite(interval) && interval > 0 ? Math.floor(interval) : 3600,
  };
}

function buildRoutingGeoIPFromForm(values) {
  const enabled = !!values?.routing_geoip_enabled;
  if (!enabled) {
    return null;
  }
  const type = String(values?.routing_geoip_type || "http").trim().toLowerCase();
  if (type !== "http" && type !== "file") {
    throw new Error("GEOIP 类型仅支持 http 或 file");
  }
  const out = {
    type,
    interval_sec: Number(values?.routing_geoip_interval_sec) > 0 ? Math.floor(Number(values.routing_geoip_interval_sec)) : 3600,
  };
  if (type === "http") {
    const url = String(values?.routing_geoip_url || "").trim();
    if (!url) {
      throw new Error("请填写 GEOIP mmdb 下载 URL");
    }
    out.url = url;
  } else {
    const path = String(values?.routing_geoip_path || "").trim();
    if (!path) {
      throw new Error("请填写 GEOIP mmdb 本地路径");
    }
    out.path = path;
  }
  return out;
}

function isLikelyRuleExpression(parts) {
  if (!Array.isArray(parts) || parts.length < 1) {
    return false;
  }
  const ruleType = String(parts[0] || "").trim().toUpperCase();
  return ROUTING_RULE_SIMPLE_TYPES.has(ruleType) || ROUTING_RULE_LOGICAL_TYPES.has(ruleType);
}

function parseLogicalChildrenExpression(ruleType, exprRaw) {
  const cleaned = unwrapOuterParentheses(exprRaw);
  if (!cleaned) {
    return [];
  }
  if (ruleType === "NOT") {
    return [cleaned];
  }
  const parts = splitRuleCSVLine(cleaned);
  if (isLikelyRuleExpression(parts)) {
    return [cleaned];
  }
  return parts
    .map((item) => unwrapOuterParentheses(item))
    .map((item) => String(item || "").trim())
    .filter(Boolean);
}

function parseLogicalChildRule(rawRule) {
  const raw = String(rawRule || "").trim();
  if (!raw) {
    return {type: "DOMAIN-SUFFIX", match_value: "", provider_name: "", raw_rule: ""};
  }
  const parts = splitRuleCSVLine(raw);
  if (parts.length === 0) {
    return {type: "ADVANCED", raw_rule: raw};
  }
  const childType = String(parts[0] || "").trim().toUpperCase();
  if (!ROUTING_RULE_SIMPLE_TYPES.has(childType)) {
    return {type: "ADVANCED", raw_rule: raw};
  }
  if (childType === "MATCH") {
    return {type: "MATCH", match_value: "", provider_name: "", raw_rule: ""};
  }
  if (childType === "RULE-SET") {
    return {
      type: "RULE-SET",
      provider_name: String(parts[1] || "").trim(),
      match_value: "",
      raw_rule: "",
    };
  }
  return {
    type: childType,
    match_value: String(parts[1] || "").trim(),
    provider_name: "",
    raw_rule: "",
  };
}

function buildLogicalChildRule(child) {
  const type = String(child?.type || "").trim().toUpperCase();
  if (!type) {
    throw new Error("子条件类型不能为空");
  }
  if (type === "ADVANCED") {
    const raw = String(child?.raw_rule || "").trim();
    if (!raw) {
      throw new Error("子条件高级规则不能为空");
    }
    return raw;
  }
  if (type === "MATCH") {
    return "MATCH";
  }
  if (type === "RULE-SET") {
    const provider = String(child?.provider_name || "").trim();
    if (!provider) {
      throw new Error("子条件必须选择规则集");
    }
    return `RULE-SET,${provider}`;
  }
  const payload = String(child?.match_value || "").trim();
  if (!payload) {
    throw new Error("子条件匹配值不能为空");
  }
  return `${type},${payload}`;
}

function defaultLogicalChild() {
  return {
    type: "DOMAIN-SUFFIX",
    match_value: "",
    provider_name: "",
    raw_rule: "",
  };
}

function parseRoutingRuleToForm(rule) {
  const raw = String(rule || "").trim();
  if (!raw) {
    return {
      rule_type: "DOMAIN-SUFFIX",
      match_value: "",
      provider_name: "",
      action_kind: "group",
      action_node: "",
      action_group: "",
      logical_children: [defaultLogicalChild()],
      raw_rule: "",
    };
  }
  const parts = splitRuleCSVLine(raw);
  if (parts.length === 0) {
    return {rule_type: "ADVANCED", raw_rule: raw};
  }
  const ruleType = String(parts[0] || "").trim().toUpperCase();
  if (!ROUTING_RULE_SIMPLE_TYPES.has(ruleType) && !ROUTING_RULE_LOGICAL_TYPES.has(ruleType)) {
    return {rule_type: "ADVANCED", raw_rule: raw};
  }

  const actionIndex = ruleType === "MATCH" ? 1 : 2;
  const actionToken = String(parts[actionIndex] || "").trim();
  const action = ruleType === "RULE-SET" && !actionToken
    ? {action_kind: "inherit", action_node: "", action_group: ""}
    : parseRuleAction(actionToken);
  const logicalChildren = ROUTING_RULE_LOGICAL_TYPES.has(ruleType)
    ? parseLogicalChildrenExpression(ruleType, String(parts[1] || "").trim()).map((child) => parseLogicalChildRule(child))
    : [defaultLogicalChild()];

  return {
    rule_type: ruleType,
    match_value: ruleType === "MATCH" ? "" : String(parts[1] || "").trim(),
    provider_name: ruleType === "RULE-SET" ? String(parts[1] || "").trim() : "",
    action_kind: action.action_kind,
    action_node: action.action_node,
    action_group: action.action_group,
    logical_children: logicalChildren.length > 0 ? logicalChildren : [defaultLogicalChild()],
    raw_rule: raw,
  };
}

function buildRoutingRuleFromForm(values) {
  const ruleType = String(values.rule_type || "").trim().toUpperCase();
  if (!ruleType) {
    throw new Error("请选择规则类型");
  }
  if (ruleType === "ADVANCED") {
    const raw = String(values.raw_rule || "").trim();
    if (!raw) {
      throw new Error("请输入规则内容");
    }
    return raw;
  }

  if (ROUTING_RULE_LOGICAL_TYPES.has(ruleType)) {
    const actionToken = buildRuleAction(values.action_kind, values.action_node, values.action_group);
    const childrenRaw = Array.isArray(values.logical_children) ? values.logical_children : [];
    const childRules = childrenRaw
      .map((child) => {
        try {
          return buildLogicalChildRule(child);
        } catch {
          return "";
        }
      })
      .map((x) => String(x || "").trim())
      .filter(Boolean);
    if (ruleType === "NOT" && childRules.length !== 1) {
      throw new Error("NOT 必须且只能有 1 个子条件");
    }
    if ((ruleType === "AND" || ruleType === "OR") && childRules.length < 2) {
      throw new Error(`${ruleType} 至少需要 2 个子条件`);
    }
    const expression = ruleType === "NOT"
      ? `(${childRules[0]})`
      : `(${childRules.map((item) => `(${item})`).join(",")})`;
    return `${ruleType},${expression},${actionToken}`;
  }

  if (ruleType === "MATCH") {
    const actionToken = buildRuleAction(values.action_kind, values.action_node, values.action_group);
    return `MATCH,${actionToken}`;
  }
  if (ruleType === "RULE-SET") {
    const provider = String(values.provider_name || "").trim();
    if (!provider) {
      throw new Error("请选择规则集");
    }
    const actionKind = String(values.action_kind || "").trim().toLowerCase();
    if (!actionKind || actionKind === "inherit") {
      return `RULE-SET,${provider}`;
    }
    const actionToken = buildRuleAction(values.action_kind, values.action_node, values.action_group);
    return `RULE-SET,${provider},${actionToken}`;
  }

  const payload = String(values.match_value || "").trim();
  if (!payload) {
    throw new Error("请输入匹配值");
  }
  const actionToken = buildRuleAction(values.action_kind, values.action_node, values.action_group);
  return `${ruleType},${payload},${actionToken}`;
}

function formatRoutingActionLabel(actionKind, actionNode, actionGroup) {
  switch (String(actionKind || "").toLowerCase()) {
    case "inherit":
      return "继承规则集动作";
    case "direct":
      return "DIRECT";
    case "reject":
      return "REJECT";
    case "proxy":
      return "PROXY";
    case "group":
      return actionGroup ? `GROUP:${actionGroup}` : "GROUP";
    case "node":
      return actionNode ? `NODE:${actionNode}` : "NODE";
    default:
      return "-";
  }
}

function normalizeRoutingGroupEgressMap(values, validNodes = []) {
  const out = {};
  const validSet = new Set((Array.isArray(validNodes) ? validNodes : []).map((x) => String(x || "").trim()).filter(Boolean));
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    return out;
  }
  Object.entries(values).forEach(([rawGroup, rawNode]) => {
    const group = String(rawGroup || "").trim();
    const node = String(rawNode || "").trim();
    if (!group || !node) {
      return;
    }
    if (validSet.size > 0 && !validSet.has(node)) {
      return;
    }
    out[group] = node;
  });
  return out;
}

function clampProbeTimeoutMS(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    return 2000;
  }
  if (n > 2000) {
    return 2000;
  }
  return Math.round(n);
}

function normalizeGroupValues(values) {
  const out = [];
  const seen = new Set();
  (Array.isArray(values) ? values : []).forEach((item) => {
    const v = String(item || "").trim();
    if (!v || seen.has(v)) {
      return;
    }
    seen.add(v);
    out.push(v);
  });
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

function getRulePayloadLabel(ruleType) {
  switch (String(ruleType || "").toUpperCase()) {
    case "DOMAIN":
      return "域名";
    case "DOMAIN-SUFFIX":
      return "域名后缀";
    case "DOMAIN-KEYWORD":
      return "域名关键词";
    case "DOMAIN-REGEX":
      return "域名正则";
    case "IP-CIDR":
      return "IPv4 网段";
    case "IP-CIDR6":
      return "IPv6 网段";
    case "GEOIP":
      return "国家码";
    case "DST-PORT":
      return "端口/端口范围";
    default:
      return "匹配值";
  }
}

function getRulePayloadPlaceholder(ruleType) {
  switch (String(ruleType || "").toUpperCase()) {
    case "DOMAIN":
      return "example.com";
    case "DOMAIN-SUFFIX":
      return "google.com";
    case "DOMAIN-KEYWORD":
      return "google";
    case "DOMAIN-REGEX":
      return ".*google.*";
    case "IP-CIDR":
      return "8.8.8.0/24";
    case "IP-CIDR6":
      return "2001:db8::/32";
    case "GEOIP":
      return "CN";
    case "DST-PORT":
      return "443 或 8000-9000";
    default:
      return "";
  }
}

function App() {
  const [isMobile, setIsMobile] = useState(typeof window !== "undefined" ? window.matchMedia("(max-width: 768px)").matches : false);
  const [booting, setBooting] = useState(true);
  const [loggedIn, setLoggedIn] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [rememberAuth, setRememberAuth] = useState(true);
  const [loading, setLoading] = useState(false);
  const [statusLoading, setStatusLoading] = useState(false);
  const [configPath, setConfigPath] = useState("");
  const [config, setConfig] = useState(null);
  const [current, setCurrent] = useState("");
  const [runtimeStatus, setRuntimeStatus] = useState(null);
  const [selected, setSelected] = useState([]);
  const [savingConfig, setSavingConfig] = useState(false);
  const [tunApplying, setTunApplying] = useState(false);
  const [tunTaskProgress, setTunTaskProgress] = useState(null);
  const [tunProgressTick, setTunProgressTick] = useState(0);
  const [savingNode, setSavingNode] = useState(false);
  const [batchDeletingNode, setBatchDeletingNode] = useState(false);
  const [probePersistKey, setProbePersistKey] = useState(() => buildProbeResultStorageKey(""));
  const [latencyResult, setLatencyResult] = useState(() => loadProbeResultStateByKey(buildProbeResultStorageKey("")).latency || {});
  const [bandwidthResult, setBandwidthResult] = useState(() => loadProbeResultStateByKey(buildProbeResultStorageKey("")).bandwidth || {});
  const [latencyLoading, setLatencyLoading] = useState({});
  const [bandwidthLoading, setBandwidthLoading] = useState({});
  const [latencyTask, setLatencyTask] = useState({running: false, current: 0, total: 0});
  const [bandwidthTask, setBandwidthTask] = useState({running: false, current: 0, total: 0});
  const [diagnoseVisible, setDiagnoseVisible] = useState(false);
  const [diagnoseRows, setDiagnoseRows] = useState([]);
  const [diagnoseSummary, setDiagnoseSummary] = useState(null);
  const [diagnoseRaw, setDiagnoseRaw] = useState(null);
  const [diagnosing, setDiagnosing] = useState(false);
  const [routeCheckVisible, setRouteCheckVisible] = useState(false);
  const [routeCheckLoading, setRouteCheckLoading] = useState(false);
  const [routeCheckRaw, setRouteCheckRaw] = useState(null);
  const [tunCheckVisible, setTunCheckVisible] = useState(false);
  const [tunCheckLoading, setTunCheckLoading] = useState(false);
  const [tunCheckRaw, setTunCheckRaw] = useState(null);
  const [tunCheckProgress, setTunCheckProgress] = useState(null);
  const [tunDNSRepairLoading, setTunDNSRepairLoading] = useState(false);
  const [routeSelfHealLoading, setRouteSelfHealLoading] = useState(false);
  const [routeSelfHealRaw, setRouteSelfHealRaw] = useState(null);
  const [exportingSelfHealReport, setExportingSelfHealReport] = useState(false);
  const [backupVisible, setBackupVisible] = useState(false);
  const [backupRows, setBackupRows] = useState([]);
  const [backupLoading, setBackupLoading] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [editNodeName, setEditNodeName] = useState("");
  const [editVisible, setEditVisible] = useState(false);
  const [configVisible, setConfigVisible] = useState(false);
  const [addNodeVisible, setAddNodeVisible] = useState(false);
  const [nodeGroupAction, setNodeGroupAction] = useState("");
  const [groupManageVisible, setGroupManageVisible] = useState(false);
  const [groupManaging, setGroupManaging] = useState(false);
  const [activeTab, setActiveTab] = useState("nodes");
  const [logLoading, setLogLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [logLevel, setLogLevel] = useState("");
  const [logSearch, setLogSearch] = useState("");
  const [logLimit, setLogLimit] = useState(300);
  const [logAutoRefresh, setLogAutoRefresh] = useState(true);
  const [logCurrentNodeOnly, setLogCurrentNodeOnly] = useState(false);
  const [subscriptions, setSubscriptions] = useState([]);
  const [subscriptionLoading, setSubscriptionLoading] = useState(false);
  const [subscriptionSaving, setSubscriptionSaving] = useState(false);
  const [subscriptionUpdatingAll, setSubscriptionUpdatingAll] = useState(false);
  const [subscriptionUpdatingIDs, setSubscriptionUpdatingIDs] = useState({});
  const [taskCenterLoading, setTaskCenterLoading] = useState(false);
  const [taskCenterItems, setTaskCenterItems] = useState([]);
  const [taskCenterQueue, setTaskCenterQueue] = useState(null);
  const [taskCenterAutoRefresh, setTaskCenterAutoRefresh] = useState(true);
  const taskCenterLoadingRef = useRef(false);
  const [subscriptionModalVisible, setSubscriptionModalVisible] = useState(false);
  const [editingSubscriptionID, setEditingSubscriptionID] = useState("");
  const [routingSaving, setRoutingSaving] = useState(false);
  const [routingUpdatingAll, setRoutingUpdatingAll] = useState(false);
  const [routingUpdatingNames, setRoutingUpdatingNames] = useState({});
  const [routingProviders, setRoutingProviders] = useState([]);
  const [routingGeoIPRuntime, setRoutingGeoIPRuntime] = useState(null);
  const [routingProviderLoading, setRoutingProviderLoading] = useState(false);
  const [routingRules, setRoutingRules] = useState([]);
  const [routingGroupEgress, setRoutingGroupEgress] = useState({});
  const [routingRuleModalVisible, setRoutingRuleModalVisible] = useState(false);
  const [editingRoutingRuleIndex, setEditingRoutingRuleIndex] = useState(-1);
  const [routingProviderConfigs, setRoutingProviderConfigs] = useState([]);
  const [routingProviderModalVisible, setRoutingProviderModalVisible] = useState(false);
  const [editingRoutingProviderName, setEditingRoutingProviderName] = useState("");
  const [routingProbeLoading, setRoutingProbeLoading] = useState(false);
  const [routingProbeResult, setRoutingProbeResult] = useState(null);
  const [routingMatchLoading, setRoutingMatchLoading] = useState(false);
  const [routingMatchResult, setRoutingMatchResult] = useState(null);
  const [egressProbeLoading, setEgressProbeLoading] = useState(false);
  const [egressProbeResult, setEgressProbeResult] = useState(null);
  const [routingHitsLoading, setRoutingHitsLoading] = useState(false);
  const [routingHits, setRoutingHits] = useState([]);
  const [routingHitsStats, setRoutingHitsStats] = useState(null);
  const [routingHitsLimit, setRoutingHitsLimit] = useState(300);
  const [routingHitsAction, setRoutingHitsAction] = useState("");
  const [routingHitsNetwork, setRoutingHitsNetwork] = useState("");
  const [routingHitsSource, setRoutingHitsSource] = useState("");
  const [routingHitsSourceClient, setRoutingHitsSourceClient] = useState("");
  const [routingHitsSearch, setRoutingHitsSearch] = useState("");
  const [routingHitsNode, setRoutingHitsNode] = useState("");
  const [routingHitsRule, setRoutingHitsRule] = useState("");
  const [routingHitsWindowSec, setRoutingHitsWindowSec] = useState(0);
  const [routingHitsAutoRefresh, setRoutingHitsAutoRefresh] = useState(true);
  const [mitmSaving, setMitmSaving] = useState(false);
  const [mitmDownloading, setMitmDownloading] = useState(false);
  const [mitmCopyingCommand, setMitmCopyingCommand] = useState(false);
  const [mitmCheckingCA, setMitmCheckingCA] = useState(false);
  const [mitmInstallingCA, setMitmInstallingCA] = useState(false);
  const [mitmCAStatus, setMitmCAStatus] = useState(null);

  const [loginForm] = Form.useForm();
  const [configForm] = Form.useForm();
  const [importForm] = Form.useForm();
  const [manualForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [probeForm] = Form.useForm();
  const [subscriptionForm] = Form.useForm();
  const [routingForm] = Form.useForm();
  const [routingRuleForm] = Form.useForm();
  const [routingProviderForm] = Form.useForm();
  const [routingMatchForm] = Form.useForm();
  const [mitmForm] = Form.useForm();
  const [groupRenameForm] = Form.useForm();
  const [groupRemoveForm] = Form.useForm();
  const probeHydratingRef = useRef(false);

  const nodes = useMemo(() => (config?.nodes || []), [config]);
  const nodeOrderMap = useMemo(() => {
    const out = {};
    (nodes || []).forEach((n, idx) => {
      if (n?.name) {
        out[n.name] = idx;
      }
    });
    return out;
  }, [nodes]);
  const groupOptions = useMemo(() => {
    const set = new Set();
    (nodes || []).forEach((node) => {
      (node?.groups || []).forEach((g) => {
        const name = String(g || "").trim();
        if (name) {
          set.add(name);
        }
      });
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b)).map((value) => ({value, label: value}));
  }, [nodes]);
  const currentNode = useMemo(() => {
    return (nodes || []).find((n) => String(n?.name || "").trim() === String(current || "").trim()) || null;
  }, [nodes, current]);
  const groupNodeMap = useMemo(() => {
    const out = {};
    (nodes || []).forEach((node) => {
      (node?.groups || []).forEach((group) => {
        const key = String(group || "").trim();
        if (!key) {
          return;
        }
        if (!out[key]) {
          out[key] = [];
        }
        out[key].push(node);
      });
    });
    return out;
  }, [nodes]);
  const groupActionNodes = useMemo(() => {
    const group = String(nodeGroupAction || "").trim();
    if (!group) {
      return [];
    }
    return (groupNodeMap[group] || []).slice();
  }, [nodeGroupAction, groupNodeMap]);
  const tunCheckMismatchRows = useMemo(() => extractTunMismatchRows(tunCheckRaw), [tunCheckRaw]);
  const tunCheckDNSProbeRows = useMemo(() => extractTunDNSProbeRows(tunCheckRaw), [tunCheckRaw]);
  const groupStatsRows = useMemo(() => (
    Object.entries(groupNodeMap || {})
      .map(([group, list]) => ({
        key: group,
        group,
        count: Array.isArray(list) ? list.length : 0,
      }))
      .sort((a, b) => a.group.localeCompare(b.group))
  ), [groupNodeMap]);
  const groupedNodeSections = useMemo(() => {
    const sections = Object.entries(groupNodeMap || {})
      .map(([group, list]) => ({
        key: group,
        group,
        nodes: Array.isArray(list) ? [...list] : [],
      }))
      .sort((a, b) => a.group.localeCompare(b.group));
    sections.forEach((section) => {
      section.nodes.sort((a, b) => {
        const ai = nodeOrderMap[a?.name] ?? 0;
        const bi = nodeOrderMap[b?.name] ?? 0;
        return ai - bi;
      });
    });
    const groupedNames = new Set();
    sections.forEach((section) => {
      (section.nodes || []).forEach((n) => {
        if (n?.name) {
          groupedNames.add(n.name);
        }
      });
    });
    const ungrouped = (nodes || []).filter((n) => n?.name && !groupedNames.has(n.name));
    if (ungrouped.length > 0) {
      sections.push({
        key: "__ungrouped__",
        group: "未分组",
        nodes: ungrouped,
      });
    }
    return sections;
  }, [groupNodeMap, nodes, nodeOrderMap]);
  const selectedGroupEgressNode = useMemo(() => {
    const group = String(nodeGroupAction || "").trim();
    if (!group) {
      return "";
    }
    return String(routingGroupEgress?.[group] || "").trim();
  }, [nodeGroupAction, routingGroupEgress]);
  const tunTaskBusy = useMemo(() => {
    const status = String(tunTaskProgress?.status || "").toLowerCase();
    return tunApplying || status === "pending" || status === "running";
  }, [tunApplying, tunTaskProgress]);
  const visibleSelected = useMemo(() => {
    const set = new Set((nodes || []).map((n) => n.name));
    return (selected || []).filter((name) => set.has(name));
  }, [selected, nodes]);
  const routingProviderRuntimeMap = useMemo(() => {
    const out = {};
    (routingProviders || []).forEach((item) => {
      if (item && item.name) {
        out[item.name] = item;
      }
    });
    return out;
  }, [routingProviders]);
  const routingUpdatingAnyItem = useMemo(() => {
    return Object.keys(routingUpdatingNames || {}).length > 0;
  }, [routingUpdatingNames]);
  const editingGeoIPProvider = useMemo(() => {
    return String(editingRoutingProviderName || "").trim().toLowerCase() === "geoip";
  }, [editingRoutingProviderName]);
  const routingProviderRows = useMemo(() => {
    const rows = (routingProviderConfigs || []).map((item) => {
      const runtime = routingProviderRuntimeMap[item.name] || {};
      return {
        key: `provider:${item.name}`,
        provider_name: item.name,
        ...item,
        ...runtime,
        auto_update: item.type === "http",
      };
    });
    const geo = config?.routing?.geoip;
    if (geo && typeof geo === "object" && !Array.isArray(geo)) {
      rows.push({
        key: "provider:geoip",
        provider_name: "geoip",
        name: "GEOIP(mmdb)",
        type: String(geo.type || "http").trim().toLowerCase() || "http",
        behavior: "geoip",
        format: "mmdb",
        url: String(geo.url || "").trim(),
        path: String(geo.path || "").trim(),
        interval_sec: Number(geo.interval_sec) > 0 ? Number(geo.interval_sec) : 3600,
        auto_update: true,
        is_geoip: true,
        updating: !!routingGeoIPRuntime?.updating,
        last_attempt: routingGeoIPRuntime?.last_attempt || "",
        last_success: routingGeoIPRuntime?.last_success || "",
        error: routingGeoIPRuntime?.error || "",
      });
    }
    return rows;
  }, [routingProviderConfigs, routingProviderRuntimeMap, config, routingGeoIPRuntime]);
  const routingGroupNames = useMemo(() => {
    const set = new Set((groupOptions || []).map((item) => String(item?.value || "").trim()).filter(Boolean));
    Object.keys(routingGroupEgress || {}).forEach((group) => {
      const name = String(group || "").trim();
      if (name) {
        set.add(name);
      }
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [groupOptions, routingGroupEgress]);
  const routingActionGroupOptions = useMemo(() => (
    routingGroupNames.map((group) => ({value: group, label: group}))
  ), [routingGroupNames]);
  const routingHitSourceClientOptions = useMemo(() => {
    const set = new Set();
    const counters = (routingHitsStats?.clients && typeof routingHitsStats.clients === "object" && !Array.isArray(routingHitsStats.clients))
      ? routingHitsStats.clients
      : {};
    Object.keys(counters).forEach((name) => {
      const key = String(name || "").trim();
      if (key && key !== "unknown") {
        set.add(key);
      }
    });
    (routingHits || []).forEach((item) => {
      const key = String(item?.source_client || "").trim();
      if (key) {
        set.add(key);
      }
    });
    const list = Array.from(set).sort((a, b) => a.localeCompare(b, undefined, {numeric: true, sensitivity: "base"}));
    return [
      {value: "", label: "全部客户端"},
      ...list.map((name) => {
        const count = Number(counters?.[name] || 0);
        return {value: name, label: count > 0 ? `${name} (${count})` : name};
      }),
    ];
  }, [routingHitsStats, routingHits]);

  useEffect(() => {
    const onResize = () => {
      if (typeof window === "undefined") {
        return;
      }
      setIsMobile(window.matchMedia("(max-width: 768px)").matches);
    };
    onResize();
    if (typeof window === "undefined") {
      return undefined;
    }
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
    };
  }, []);

  useEffect(() => {
    setSelected((prev) => {
      const set = new Set((nodes || []).map((n) => n.name));
      return (prev || []).filter((name) => set.has(name));
    });
    if (nodeGroupAction && !(groupNodeMap[nodeGroupAction] || []).length) {
      setNodeGroupAction("");
    }
  }, [nodes, groupNodeMap, nodeGroupAction]);

  useEffect(() => {
    const kind = String(routingForm.getFieldValue("routing_default_action_kind") || "group").trim().toLowerCase();
    const current = String(routingForm.getFieldValue("routing_default_action_group") || "").trim();
    if (kind !== "group") {
      return;
    }
    if (routingGroupNames.length === 0) {
      if (current) {
        routingForm.setFieldsValue({routing_default_action_group: ""});
      }
      return;
    }
    if (current && routingGroupNames.includes(current)) {
      return;
    }
    const preferred = pickPreferredRoutingGroup(routingGroupNames);
    if (preferred) {
      routingForm.setFieldsValue({routing_default_action_group: preferred});
    }
  }, [routingGroupNames, routingForm]);

  useEffect(() => {
    const nextKey = buildProbeResultStorageKey(configPath);
    if (nextKey === probePersistKey) {
      return;
    }
    const restored = loadProbeResultStateByKey(nextKey);
    probeHydratingRef.current = true;
    setProbePersistKey(nextKey);
    setLatencyResult(restored.latency || {});
    setBandwidthResult(restored.bandwidth || {});
  }, [configPath, probePersistKey]);

  useEffect(() => {
    if (probeHydratingRef.current) {
      probeHydratingRef.current = false;
      return;
    }
    saveProbeResultStateByKey(probePersistKey, latencyResult, bandwidthResult);
  }, [probePersistKey, latencyResult, bandwidthResult]);

  function providerMapToRows(providerMap) {
    const entries = Object.entries(providerMap || {});
    entries.sort((a, b) => a[0].localeCompare(b[0]));
    return entries.map(([name, item]) => ({
      name,
      type: item?.type || "",
      behavior: item?.behavior || "",
      format: item?.format || "auto",
      url: item?.url || "",
      path: item?.path || "",
      interval_sec: item?.interval_sec || 3600,
      header: item?.header || undefined,
    }));
  }

  async function submitLogin() {
    const values = await loginForm.validateFields();
    const username = (values.username || "").trim();
    const password = values.password || "";
    setLoginLoading(true);
    setLoginError("");
    try {
      await api("/api/v1/current", {
        suppressAuthEvent: true,
        headers: {
          Authorization: toBasicAuth(username, password)
        }
      });
      saveAuth(username, password, rememberAuth);
      setLoggedIn(true);
    } catch (err) {
      setLoginError(`登录失败: ${err.message}`);
    } finally {
      setLoginLoading(false);
    }
  }

  async function logout() {
    clearSavedAuth();
    setLoginError("");
    setRuntimeStatus(null);
    loginForm.setFieldsValue({password: ""});
    try {
      await api("/api/v1/current", {suppressAuthEvent: true});
      setLoggedIn(true);
    } catch {
      setLoggedIn(false);
    }
  }

  async function refreshAll() {
    setLoading(true);
    try {
      const data = await api("/api/v1/config");
      setConfigPath(data.config_path || "");
      setConfig(data.config || null);
      setCurrent(data.current || "");
      if (data.config) {
        const routing = data.config.routing || {};
        const routingDefault = parseRoutingDefaultActionToForm(routing.default_action || "");
        const routingGeoIP = parseRoutingGeoIPToForm(routing.geoip);
        const mitm = data.config.mitm || {};
        const mitmDoHDoT = mitm.doh_dot || {};
        configForm.setFieldsValue({
          listen: data.config.listen,
          control: data.config.control,
          web_username: data.config.web_username || "",
          web_password: data.config.web_password || "",
          min_idle_session: data.config.min_idle_session,
          default_node: data.config.default_node,
          tun_enabled: !!data.config.tun?.enabled,
          tun_name: data.config.tun?.name || "anytls0",
          tun_mtu: data.config.tun?.mtu || 1500,
          tun_address: data.config.tun?.address || "198.18.0.1/15",
          tun_auto_route: !!data.config.tun?.auto_route,
          tun_disable_other_proxies: !!data.config.tun?.disable_other_proxies,
          failover_enabled: !!data.config.failover?.enabled,
          failover_check_interval_sec: data.config.failover?.check_interval_sec || 15,
          failover_failure_threshold: data.config.failover?.failure_threshold || 2,
          failover_probe_target: data.config.failover?.probe_target || "1.1.1.1:443",
          failover_probe_timeout_ms: data.config.failover?.probe_timeout_ms || 2500,
          failover_best_latency_enabled: !!data.config.failover?.best_latency_enabled,
        });
        routingForm.setFieldsValue({
          routing_enabled: !!routing.enabled,
          routing_default_action_kind: routingDefault.kind,
          routing_default_action_group: routingDefault.group,
          routing_geoip_enabled: routingGeoIP.enabled,
          routing_geoip_type: routingGeoIP.type,
          routing_geoip_url: routingGeoIP.url,
          routing_geoip_path: routingGeoIP.path,
          routing_geoip_interval_sec: routingGeoIP.interval_sec,
        });
        setRoutingRules(Array.isArray(routing.rules) ? routing.rules : []);
        setRoutingProviderConfigs(providerMapToRows(routing.rule_providers || {}));
        setRoutingGroupEgress(normalizeRoutingGroupEgressMap(routing.group_egress || {}, (data.config.nodes || []).map((n) => n.name)));
        mitmForm.setFieldsValue({
          mitm_enabled: !!mitm.enabled,
          mitm_listen: mitm.listen || "127.0.0.1:1090",
          mitm_hosts: Array.isArray(mitm.hosts) ? mitm.hosts.join("\n") : "",
          mitm_url_reject: Array.isArray(mitm.url_reject) ? mitm.url_reject.join("\n") : "",
          mitm_doh_dot_enabled: !!mitmDoHDoT.enabled,
          mitm_doh_hosts: Array.isArray(mitmDoHDoT.doh_hosts) ? mitmDoHDoT.doh_hosts.join("\n") : "",
          mitm_dot_hosts: Array.isArray(mitmDoHDoT.dot_hosts) ? mitmDoHDoT.dot_hosts.join("\n") : "",
        });
      }
      if (!data.config?.routing) {
        routingForm.setFieldsValue({
          routing_enabled: false,
          routing_default_action_kind: "group",
          routing_default_action_group: "",
          routing_geoip_enabled: false,
          routing_geoip_type: "http",
          routing_geoip_url: "",
          routing_geoip_path: "",
          routing_geoip_interval_sec: 3600,
        });
        setRoutingRules([]);
        setRoutingProviderConfigs([]);
        setRoutingGroupEgress({});
      }
      await refreshStatus();
      await loadMITMCAStatus({silent: true});
      await loadRoutingProviders();
    } catch (err) {
      if (err?.status !== 401) {
        message.error(`加载失败: ${err.message}`);
      }
    } finally {
      setLoading(false);
    }
  }

  async function refreshStatus() {
    setStatusLoading(true);
    try {
      const data = await api("/api/v1/status");
      setRuntimeStatus(data || null);
    } catch (err) {
      setRuntimeStatus(null);
    } finally {
      setStatusLoading(false);
    }
  }

  async function loadMITMCAStatus(options = {}) {
    const {silent = false} = options;
    setMitmCheckingCA(true);
    try {
      const data = await api("/api/v1/mitm/ca/status");
      setMitmCAStatus(data || null);
      return data || null;
    } catch (err) {
      setMitmCAStatus(null);
      if (!silent) {
        message.error(`检测 CA 状态失败: ${err.message}`);
      }
      return null;
    } finally {
      setMitmCheckingCA(false);
    }
  }

  async function autoInstallMITMCA() {
    setMitmInstallingCA(true);
    try {
      const res = await api("/api/v1/mitm/ca/install", {
        method: "POST",
        body: JSON.stringify({}),
        timeoutMS: 60000,
      });
      const status = res?.status || null;
      if (status) {
        setMitmCAStatus(status);
      } else {
        await loadMITMCAStatus({silent: true});
      }
      message.success(String(res?.message || "MITM CA 自动安装完成"));
    } catch (err) {
      message.error(`自动安装 CA 失败: ${err.message}`);
    } finally {
      setMitmInstallingCA(false);
    }
  }

  useEffect(() => {
    const onUnauthorized = () => {
      setLoggedIn(false);
      setLoginError("登录已失效，请重新登录");
      setBooting(false);
    };
    window.addEventListener("anytls-auth-unauthorized", onUnauthorized);
    return () => window.removeEventListener("anytls-auth-unauthorized", onUnauthorized);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function bootstrapAuth() {
      const saved = loadSavedAuth();
      if (saved) {
        loginForm.setFieldsValue({
          username: saved.username,
          password: saved.password,
        });
        setRememberAuth(!!window.localStorage.getItem(WEB_AUTH_STORAGE_KEY));
      }

      try {
        await api("/api/v1/current", {suppressAuthEvent: true});
        if (cancelled) {
          return;
        }
        setLoggedIn(true);
        setBooting(false);
      } catch (err) {
        if (cancelled) {
          return;
        }
        if (err?.status === 401) {
          setLoggedIn(false);
          setBooting(false);
          return;
        }
        setBooting(false);
        message.error(`连接失败: ${err.message}`);
      }
    }
    bootstrapAuth();
    return () => { cancelled = true; };
  }, [loginForm]);

  useEffect(() => {
    if (!loggedIn) {
      return undefined;
    }
    refreshAll();
    const timer = setInterval(() => { refreshStatus(); }, 15000);
    return () => clearInterval(timer);
  }, [loggedIn]);

  useEffect(() => {
    const latest = runtimeStatus?.routing?.egress_probe_last;
    if (!latest || typeof latest !== "object" || Array.isArray(latest)) {
      return;
    }
    setEgressProbeResult(latest);
  }, [runtimeStatus]);

  async function saveConfig() {
    const values = await configForm.validateFields();
    setSavingConfig(true);
    try {
      const payload = {
        listen: values.listen,
        control: values.control,
        web_username: values.web_username || "",
        web_password: values.web_password || "",
        min_idle_session: values.min_idle_session,
        default_node: values.default_node,
        tun: {
          enabled: !!values.tun_enabled,
          name: values.tun_name,
          mtu: values.tun_mtu,
          address: values.tun_address,
          auto_route: !!values.tun_auto_route,
          disable_other_proxies: !!values.tun_disable_other_proxies,
        },
        failover: {
          enabled: !!values.failover_enabled,
          check_interval_sec: values.failover_check_interval_sec || 15,
          failure_threshold: values.failover_failure_threshold || 2,
          probe_target: values.failover_probe_target || "1.1.1.1:443",
          probe_timeout_ms: values.failover_probe_timeout_ms || 2500,
          best_latency_enabled: !!values.failover_best_latency_enabled,
        }
      };
      const res = await api("/api/v1/config", {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      setConfig(res.config || config);
      setCurrent(res.current || current);
      setConfigVisible(false);
      message.success(res.restart_required ? "配置已保存（部分变更需重启 API 才生效）" : "配置已保存");
    } catch (err) {
      message.error(`保存失败: ${err.message}`);
    } finally {
      setSavingConfig(false);
    }
  }

  async function saveRoutingConfig() {
    const values = await routingForm.validateFields();
    let defaultAction = "";
    let geoip = null;
    try {
      const actionKind = String(values.routing_default_action_kind || "group").trim().toLowerCase();
      if (actionKind === "group" && !routingGroupNames.length) {
        message.error("请先在节点里配置分组，再设置兜底分组");
        return;
      }
      defaultAction = buildRoutingDefaultActionFromForm(values.routing_default_action_kind, values.routing_default_action_group);
      geoip = buildRoutingGeoIPFromForm(values);
    } catch (err) {
      message.error(err.message || "规则分流配置无效");
      return;
    }
    const rules = (routingRules || [])
      .map((x) => String(x || "").trim())
      .filter((x) => x && !x.startsWith("#"));
    const providers = {};
    (routingProviderConfigs || []).forEach((item) => {
      const name = String(item?.name || "").trim();
      if (!name) {
        return;
      }
      const p = {
        type: item.type || "http",
        format: "auto",
      };
      const behavior = String(item.behavior || "").trim();
      if (behavior) {
        p.behavior = behavior;
      }
      if (p.type === "http") {
        p.url = String(item.url || "").trim();
        p.interval_sec = Number(item.interval_sec) > 0 ? Number(item.interval_sec) : 3600;
      } else if (p.type === "file") {
        p.path = String(item.path || "").trim();
      }
      if (item.header && typeof item.header === "object" && !Array.isArray(item.header)) {
        p.header = item.header;
      }
      providers[name] = p;
    });
    const groupEgress = normalizeRoutingGroupEgressMap(routingGroupEgress, (nodes || []).map((n) => n.name));

    setRoutingSaving(true);
    try {
      const res = await api("/api/v1/config", {
        method: "PUT",
        body: JSON.stringify({
          routing: {
            enabled: !!values.routing_enabled,
            rules,
            rule_providers: providers,
            group_egress: groupEgress,
            default_action: defaultAction,
            ...(geoip ? {geoip} : {}),
          }
        })
      });
      setConfig(res.config || config);
      setCurrent(res.current || current);
      const nextRouting = res.config?.routing || {};
      const nextDefaultAction = parseRoutingDefaultActionToForm(nextRouting.default_action || "");
      const nextRoutingGeoIP = parseRoutingGeoIPToForm(nextRouting.geoip);
      setRoutingRules(Array.isArray(nextRouting.rules) ? nextRouting.rules : []);
      setRoutingProviderConfigs(providerMapToRows(nextRouting.rule_providers || {}));
      setRoutingGroupEgress(normalizeRoutingGroupEgressMap(nextRouting.group_egress || {}, (res.config?.nodes || []).map((n) => n.name)));
      routingForm.setFieldsValue({
        routing_enabled: !!nextRouting.enabled,
        routing_default_action_kind: nextDefaultAction.kind,
        routing_default_action_group: nextDefaultAction.group,
        routing_geoip_enabled: nextRoutingGeoIP.enabled,
        routing_geoip_type: nextRoutingGeoIP.type,
        routing_geoip_url: nextRoutingGeoIP.url,
        routing_geoip_path: nextRoutingGeoIP.path,
        routing_geoip_interval_sec: nextRoutingGeoIP.interval_sec,
      });
      message.success("规则分流配置已保存并立即生效");
      await refreshStatus();
      await loadRoutingProviders();
    } catch (err) {
      message.error(`保存规则分流失败: ${err.message}`);
    } finally {
      setRoutingSaving(false);
    }
  }

  async function saveRoutingGroupEgressMap(groupEgress, successMessage = "分组当前节点已保存并生效") {
    const baseRouting = config?.routing || {};
    let fallbackDefaultAction = "";
    try {
      fallbackDefaultAction = buildRoutingDefaultActionFromForm(
        routingForm.getFieldValue("routing_default_action_kind"),
        routingForm.getFieldValue("routing_default_action_group"),
      );
    } catch {
      // ignore form invalid state and fallback to saved config/default group
    }
    if (!fallbackDefaultAction) {
      const currentConfigAction = parseRoutingDefaultActionToForm(String(baseRouting.default_action || ""));
      if (currentConfigAction.kind === "direct") {
        fallbackDefaultAction = "DIRECT";
      } else if (currentConfigAction.kind === "reject") {
        fallbackDefaultAction = "REJECT";
      } else {
        const fallbackGroup = currentConfigAction.group || pickPreferredRoutingGroup(routingGroupNames);
        if (fallbackGroup) {
          fallbackDefaultAction = `GROUP:${fallbackGroup}`;
        }
      }
    }
    const payloadRouting = {
      enabled: !!baseRouting.enabled,
      rules: Array.isArray(baseRouting.rules) ? baseRouting.rules : [],
      rule_providers: (baseRouting.rule_providers && typeof baseRouting.rule_providers === "object") ? baseRouting.rule_providers : {},
      group_egress: normalizeRoutingGroupEgressMap(groupEgress, (nodes || []).map((n) => n.name)),
      default_action: fallbackDefaultAction,
      ...((baseRouting.geoip && typeof baseRouting.geoip === "object" && !Array.isArray(baseRouting.geoip)) ? {geoip: baseRouting.geoip} : {}),
    };
    setRoutingSaving(true);
    try {
      const res = await api("/api/v1/config", {
        method: "PUT",
        body: JSON.stringify({
          routing: payloadRouting,
        })
      });
      setConfig(res.config || config);
      setCurrent(res.current || current);
      const nextRouting = res.config?.routing || {};
      const nextDefaultAction = parseRoutingDefaultActionToForm(nextRouting.default_action || "");
      const nextRoutingGeoIP = parseRoutingGeoIPToForm(nextRouting.geoip);
      setRoutingRules(Array.isArray(nextRouting.rules) ? nextRouting.rules : []);
      setRoutingProviderConfigs(providerMapToRows(nextRouting.rule_providers || {}));
      setRoutingGroupEgress(normalizeRoutingGroupEgressMap(nextRouting.group_egress || {}, (res.config?.nodes || []).map((n) => n.name)));
      routingForm.setFieldsValue({
        routing_enabled: !!nextRouting.enabled,
        routing_default_action_kind: nextDefaultAction.kind,
        routing_default_action_group: nextDefaultAction.group,
        routing_geoip_enabled: nextRoutingGeoIP.enabled,
        routing_geoip_type: nextRoutingGeoIP.type,
        routing_geoip_url: nextRoutingGeoIP.url,
        routing_geoip_path: nextRoutingGeoIP.path,
        routing_geoip_interval_sec: nextRoutingGeoIP.interval_sec,
      });
      message.success(successMessage);
      await refreshStatus();
      await loadRoutingProviders();
      return true;
    } catch (err) {
      message.error(`保存分组当前节点失败: ${err.message}`);
      return false;
    } finally {
      setRoutingSaving(false);
    }
  }

  async function runEgressQuickProbe(target = "", expectedNode = "", silent = false) {
    const probeFormValues = probeForm.getFieldsValue();
    const probeTarget = String(target || probeFormValues?.egress_probe_target || DEFAULT_EGRESS_PROBE_TARGET).trim() || DEFAULT_EGRESS_PROBE_TARGET;
    setEgressProbeLoading(true);
    try {
      const res = await api("/api/v1/routing/egress_probe", {
        method: "POST",
        body: JSON.stringify({
          target: probeTarget,
          timeout_ms: 3500,
        }),
      });
      setEgressProbeResult(res || null);
      if (!silent) {
        const ok = !!res?.ok;
        const action = String(res?.action || "").toUpperCase();
        const node = String(res?.node || "").trim();
        const statusCode = Number(res?.status_code || 0);
        const rule = String(res?.rule || "").trim();
        const errText = String(res?.error || "").trim();
        if (ok) {
          message.success(`出口验证成功: ${action || "-"} ${node || "-"} ${statusCode > 0 ? `(HTTP ${statusCode})` : ""}${rule ? `（${rule}）` : ""}`);
        } else if (String(expectedNode || "").trim() && node && node !== String(expectedNode || "").trim()) {
          message.warning(`出口验证未按预期命中: 当前 ${node}，期望 ${expectedNode}${rule ? `（${rule}）` : ""}`);
        } else {
          message.warning(`出口验证失败: ${action || "-"} ${node || "-"}${errText ? ` · ${errText}` : ""}`);
        }
      }
      return res;
    } catch (err) {
      setEgressProbeResult({
        ok: false,
        error: err.message,
        time: new Date().toISOString(),
      });
      if (!silent) {
        message.warning(`出口验证失败: ${err.message}`);
      }
      return null;
    } finally {
      setEgressProbeLoading(false);
    }
  }

  async function runRoutingMatchQuick(expectedNode = "") {
    try {
      const verify = await api("/api/v1/routing/match", {
        method: "POST",
        body: JSON.stringify({
          target: "www.google.com:443",
          network: "tcp",
          record: false,
        }),
      });
      const action = String(verify?.action || "").toUpperCase();
      const node = String(verify?.node || "").trim();
      const rule = String(verify?.rule || "").trim();
      const ok = !!expectedNode && action === "NODE" && node === String(expectedNode || "").trim();
      return {ok, action, node, rule, error: ""};
    } catch (err) {
      return {ok: false, action: "", node: "", rule: "", error: String(err?.message || err || "")};
    }
  }

  async function forceReconnectCurrentNode() {
    const nodeName = String(runtimeStatus?.current || current || "").trim();
    if (!nodeName) {
      return false;
    }
    try {
      await api("/api/v1/switch", {
        method: "POST",
        body: JSON.stringify({name: nodeName}),
      });
      return true;
    } catch (err) {
      message.warning(`强制重连失败: ${err.message}`);
      return false;
    }
  }

  async function setGroupEgressAndSave(group, nodeName) {
    const groupName = String(group || "").trim();
    const target = String(nodeName || "").trim();
    if (!groupName || !target) {
      return;
    }
    const next = {...(routingGroupEgress || {}), [groupName]: target};
    setRoutingGroupEgress(next);
    const ok = await saveRoutingGroupEgressMap(next, `已将分组 ${groupName} 出口切换到 ${target}`);
    if (!ok) {
      return;
    }

    const firstMatch = await runRoutingMatchQuick(target);
    const firstProbe = await runEgressQuickProbe("", target, true);
    const firstProbeNode = String(firstProbe?.node || "").trim();
    const firstProbeOK = !!firstProbe?.ok && firstProbeNode === target;
    if (firstMatch.ok && firstProbeOK) {
      message.success(`切换生效：命中 ${target}${firstMatch.rule ? `（${firstMatch.rule}）` : ""}`);
      return;
    }

    if (firstMatch.error) {
      message.warning(`首次路由校验失败: ${firstMatch.error}`);
    } else {
      message.warning(`首次路由校验未命中：${firstMatch.action || "-"} ${firstMatch.node || "-"}${firstMatch.rule ? `（${firstMatch.rule}）` : ""}`);
    }
    if (firstProbe && !firstProbeOK) {
      const probeErr = String(firstProbe?.error || "").trim();
      message.warning(`首次出口验证未命中：${firstProbeNode || "-"}${probeErr ? ` · ${probeErr}` : ""}`);
    }

    message.info("检测到切换未完全生效，正在自动重连并复检…");
    const reconnectOK = await forceReconnectCurrentNode();
    if (!reconnectOK) {
      return;
    }
    await refreshStatus();
    await new Promise((resolve) => setTimeout(resolve, 800));

    const secondMatch = await runRoutingMatchQuick(target);
    const secondProbe = await runEgressQuickProbe("", target, true);
    const secondProbeNode = String(secondProbe?.node || "").trim();
    const secondProbeOK = !!secondProbe?.ok && secondProbeNode === target;
    if (secondMatch.ok && secondProbeOK) {
      message.success(`已自动重连并生效：命中 ${target}${secondMatch.rule ? `（${secondMatch.rule}）` : ""}`);
      return;
    }

    const secondMatchText = secondMatch.error
      ? `路由复检失败: ${secondMatch.error}`
      : `路由复检: ${secondMatch.action || "-"} ${secondMatch.node || "-"}${secondMatch.rule ? `（${secondMatch.rule}）` : ""}`;
    const secondProbeErr = String(secondProbe?.error || "").trim();
    const secondProbeText = `出口复检: ${secondProbeNode || "-"}${secondProbeErr ? ` · ${secondProbeErr}` : ""}`;
    message.warning(`切换后仍未完全生效。${secondMatchText}；${secondProbeText}`);
  }

  function openAddRoutingRule() {
    setEditingRoutingRuleIndex(-1);
    routingRuleForm.setFieldsValue({
      rule_type: "DOMAIN-SUFFIX",
      match_value: "",
      provider_name: "",
      action_kind: "group",
      action_node: "",
      action_group: String(routingActionGroupOptions?.[0]?.value || ""),
      logical_children: [defaultLogicalChild()],
      raw_rule: "",
    });
    setRoutingRuleModalVisible(true);
  }

  function openEditRoutingRule(index) {
    const idx = Number(index);
    if (!Number.isInteger(idx) || idx < 0 || idx >= routingRules.length) {
      return;
    }
    setEditingRoutingRuleIndex(idx);
    routingRuleForm.setFieldsValue(parseRoutingRuleToForm(routingRules[idx]));
    setRoutingRuleModalVisible(true);
  }

  async function saveRoutingRule() {
    const values = await routingRuleForm.validateFields();
    let rule = "";
    try {
      rule = buildRoutingRuleFromForm(values);
    } catch (err) {
      message.error(err?.message || "规则无效");
      return;
    }
    setRoutingRules((prev) => {
      const next = [...(prev || [])];
      if (editingRoutingRuleIndex >= 0 && editingRoutingRuleIndex < next.length) {
        next[editingRoutingRuleIndex] = rule;
      } else {
        next.push(rule);
      }
      return next;
    });
    setRoutingRuleModalVisible(false);
  }

  function deleteRoutingRule(index) {
    const idx = Number(index);
    if (!Number.isInteger(idx) || idx < 0) {
      return;
    }
    setRoutingRules((prev) => (prev || []).filter((_, i) => i !== idx));
  }

  function openAddRoutingProvider() {
    setEditingRoutingProviderName("");
    setRoutingProbeResult(null);
    routingProviderForm.setFieldsValue({
      name: "",
      type: "http",
      behavior: "",
      url: "",
      path: "",
      interval_sec: 3600,
    });
    setRoutingProviderModalVisible(true);
  }

  function openEditRoutingProvider(name) {
    const targetName = String(name || "").trim();
    if (!targetName) {
      return;
    }
    if (targetName.toLowerCase() === "geoip") {
      const fallbackGeoIP = parseRoutingGeoIPToForm(config?.routing?.geoip);
      const geoValues = routingForm.getFieldsValue([
        "routing_geoip_enabled",
        "routing_geoip_type",
        "routing_geoip_url",
        "routing_geoip_path",
        "routing_geoip_interval_sec",
      ]);
      const enabled = typeof geoValues?.routing_geoip_enabled === "boolean" ? geoValues.routing_geoip_enabled : fallbackGeoIP.enabled;
      const geoTypeRaw = String(geoValues?.routing_geoip_type || fallbackGeoIP.type || "http").trim().toLowerCase();
      const geoType = geoTypeRaw === "file" ? "file" : "http";
      const geoURL = String(geoValues?.routing_geoip_url || fallbackGeoIP.url || "").trim();
      const geoPath = String(geoValues?.routing_geoip_path || fallbackGeoIP.path || "").trim();
      const geoIntervalRaw = Number(geoValues?.routing_geoip_interval_sec);
      const geoInterval = geoIntervalRaw > 0 ? Math.floor(geoIntervalRaw) : (fallbackGeoIP.interval_sec || 3600);
      setEditingRoutingProviderName("geoip");
      setRoutingProbeResult(null);
      routingProviderForm.setFieldsValue({
        name: "geoip",
        type: geoType,
        behavior: "",
        url: geoURL,
        path: geoPath,
        interval_sec: geoInterval,
        geoip_enabled: enabled !== false,
      });
      setRoutingProviderModalVisible(true);
      return;
    }
    const row = (routingProviderConfigs || []).find((x) => x.name === targetName);
    if (!row) {
      return;
    }
    setEditingRoutingProviderName(targetName);
    setRoutingProbeResult(null);
    routingProviderForm.setFieldsValue({
      name: row.name,
      type: row.type || "http",
      behavior: row.behavior || "",
      url: row.url || "",
      path: row.path || "",
      interval_sec: row.interval_sec || 3600,
    });
    setRoutingProviderModalVisible(true);
  }

  async function saveRoutingProvider() {
    const values = await routingProviderForm.validateFields();
    const nextName = String(values.name || "").trim();
    const nextType = values.type || "http";
    if (!nextName) {
      message.error("规则集名称不能为空");
      return;
    }
    const next = {
      name: nextName,
      type: nextType,
      behavior: String(values.behavior || "").trim(),
      format: "auto",
      url: nextType === "http" ? String(values.url || "").trim() : "",
      path: nextType === "file" ? String(values.path || "").trim() : "",
      interval_sec: nextType === "http" ? (Number(values.interval_sec) > 0 ? Number(values.interval_sec) : 3600) : 3600,
    };
    if (next.type === "http" && !next.url) {
      message.error("HTTP 规则集必须填写 URL");
      return;
    }
    if (next.type === "file" && !next.path) {
      message.error("本地规则集必须填写文件路径");
      return;
    }
    if (String(editingRoutingProviderName || "").toLowerCase() === "geoip") {
      const geoType = next.type === "file" ? "file" : "http";
      routingForm.setFieldsValue({
        routing_geoip_enabled: true,
        routing_geoip_type: geoType,
        routing_geoip_url: geoType === "http" ? next.url : "",
        routing_geoip_path: geoType === "file" ? next.path : "",
        routing_geoip_interval_sec: Number(next.interval_sec) > 0 ? Math.floor(Number(next.interval_sec)) : 3600,
      });
      setRoutingProviderModalVisible(false);
      setRoutingProbeResult(null);
      message.info("GEOIP 配置已更新，请点击“保存规则配置”使修改生效");
      return;
    }
    setRoutingProviderConfigs((prev) => {
      const currentRows = [...(prev || [])];
      const oldName = editingRoutingProviderName;
      const filtered = currentRows.filter((item) => item.name !== oldName && item.name !== nextName);
      filtered.push(next);
      filtered.sort((a, b) => a.name.localeCompare(b.name));
      return filtered;
    });
    setRoutingProviderModalVisible(false);
    setRoutingProbeResult(null);
  }

  function deleteRoutingProvider(name) {
    setRoutingProviderConfigs((prev) => (prev || []).filter((item) => item.name !== name));
  }

  async function probeRoutingProviderSource() {
    if (!ensureTunTaskIdle("进行规则探测")) {
      return;
    }
    const values = routingProviderForm.getFieldsValue();
    const providerType = values.type || "http";
    if (providerType === "http" && !String(values.url || "").trim()) {
      message.error("请先输入规则 URL");
      return;
    }
    if (providerType === "file" && !String(values.path || "").trim()) {
      message.error("请先输入本地文件路径");
      return;
    }

    setRoutingProbeLoading(true);
    try {
      const taskResp = await api("/api/v1/routing/probe?async=1", {
        method: "POST",
        timeoutMS: 45000,
        body: JSON.stringify({
          type: providerType,
          behavior: String(values.behavior || "").trim(),
          format: "auto",
          url: String(values.url || "").trim(),
          path: String(values.path || "").trim(),
        })
      });
      const taskID = String(taskResp?.task_id || "").trim();
      const task = taskID ? await waitTaskDone(taskID, {timeoutMS: 45000}) : null;
      const res = task?.result || null;
      setRoutingProbeResult(res || null);
      if (!String(values.behavior || "").trim() && res?.suggested_behavior) {
        routingProviderForm.setFieldsValue({behavior: res.suggested_behavior});
      }
      message.success("规则集探测完成");
    } catch (err) {
      setRoutingProbeResult(null);
      message.error(`规则集探测失败: ${err.message}`);
    } finally {
      setRoutingProbeLoading(false);
    }
  }

  async function updateRoutingProvidersNow() {
    if (!ensureTunTaskIdle("更新规则集")) {
      return;
    }
    if (routingUpdatingAnyItem) {
      message.warning("有规则集正在更新，请稍后再试");
      return;
    }
    setRoutingUpdatingAll(true);
    try {
      const taskResp = await api("/api/v1/routing/update?async=1", {
        method: "POST",
        body: JSON.stringify({})
      });
      const taskID = String(taskResp?.task_id || "").trim();
      const task = taskID ? await waitTaskDone(taskID) : null;
      const res = task?.result || {};
      const count = Number(res.count || 0);
      const snapshot = await loadRoutingProviders();
      const providerErrors = (snapshot?.providers || [])
        .filter((item) => String(item?.error || "").trim())
        .map((item) => `${item.name}: ${item.error}`);
      const geoipError = String(snapshot?.geoip?.error || "").trim();
      if (providerErrors.length > 0 || geoipError) {
        const parts = [...providerErrors];
        if (geoipError) {
          parts.push(`GEOIP(mmdb): ${geoipError}`);
        }
        message.warning(`更新请求已执行，但仍有异常项: ${parts.join(" ; ")}`);
      } else if (!res.updated) {
        message.info(count > 0 ? "规则集状态已刷新（本次无新更新）" : "当前无可更新规则集");
      } else {
        message.success(`规则集更新完成（${count} 个）`);
      }
      await refreshStatus();
    } catch (err) {
      message.error(`规则集更新失败: ${err.message}`);
    } finally {
      setRoutingUpdatingAll(false);
    }
  }

  async function updateSingleRoutingProvider(name) {
    const targetName = String(name || "").trim();
    if (!targetName) {
      return;
    }
    if (!ensureTunTaskIdle("更新规则集")) {
      return;
    }
    if (routingUpdatingAll) {
      message.warning("全量更新进行中，请稍后再试");
      return;
    }
    if (routingUpdatingNames[targetName]) {
      return;
    }
    setRoutingUpdatingNames((prev) => ({...prev, [targetName]: true}));
    try {
      const taskResp = await api("/api/v1/routing/update?async=1", {
        method: "POST",
        body: JSON.stringify({providers: [targetName]})
      });
      const taskID = String(taskResp?.task_id || "").trim();
      const result = taskID ? (await waitTaskDone(taskID))?.result || {} : {};
      const targetLabel = String(targetName).toLowerCase() === "geoip" ? "GEOIP(mmdb)" : `规则集 ${targetName}`;
      const snapshot = await loadRoutingProviders();
      let targetError = "";
      if (String(targetName).toLowerCase() === "geoip") {
        targetError = String(snapshot?.geoip?.error || "").trim();
      } else {
        const provider = (snapshot?.providers || []).find((item) => String(item?.name || "") === targetName);
        targetError = String(provider?.error || "").trim();
      }
      if (targetError) {
        message.warning(`${targetLabel} 更新请求已执行，但当前状态仍异常: ${targetError}`);
      } else if (!result.updated) {
        message.info(`${targetLabel} 已检查完成（本次无新更新）`);
      } else {
        message.success(`${targetLabel} 已更新`);
      }
      await refreshStatus();
    } catch (err) {
      message.error(`更新 ${targetName} 失败: ${err.message}`);
    } finally {
      setRoutingUpdatingNames((prev) => {
        const next = {...prev};
        delete next[targetName];
        return next;
      });
    }
  }

  async function loadRoutingProviders() {
    setRoutingProviderLoading(true);
    try {
      const res = await api("/api/v1/routing/providers");
      const providers = Array.isArray(res.providers) ? res.providers : [];
      const geoip = res && typeof res.geoip === "object" ? res.geoip : null;
      setRoutingProviders(providers);
      setRoutingGeoIPRuntime(geoip);
      return {providers, geoip};
    } catch (err) {
      setRoutingProviders([]);
      setRoutingGeoIPRuntime(null);
      return {providers: [], geoip: null};
    } finally {
      setRoutingProviderLoading(false);
    }
  }

  async function testRoutingMatch() {
    const values = await routingMatchForm.validateFields();
    const payload = {
      target: String(values.target || "").trim(),
      network: String(values.network || "tcp").trim().toLowerCase(),
      record: values.record !== false,
    };
    if (!payload.target) {
      message.error("请输入目标地址");
      return;
    }
    setRoutingMatchLoading(true);
    try {
      const res = await api("/api/v1/routing/match", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      setRoutingMatchResult(res || null);
      message.success("命中测试完成");
      await loadRoutingHits();
    } catch (err) {
      setRoutingMatchResult(null);
      message.error(`命中测试失败: ${err.message}`);
    } finally {
      setRoutingMatchLoading(false);
    }
  }

  async function loadRoutingHits() {
    setRoutingHitsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", String(routingHitsLimit || 300));
      if (routingHitsAction) {
        params.set("action", routingHitsAction);
      }
      if (routingHitsNetwork) {
        params.set("network", routingHitsNetwork);
      }
      if (routingHitsSource) {
        params.set("source", routingHitsSource);
      }
      if (routingHitsSourceClient) {
        params.set("source_client", routingHitsSourceClient);
      }
      if (routingHitsSearch) {
        params.set("search", routingHitsSearch);
      }
      if (routingHitsNode) {
        params.set("node", routingHitsNode);
      }
      if (routingHitsRule) {
        params.set("rule", routingHitsRule);
      }
      if (Number(routingHitsWindowSec) > 0) {
        params.set("window_sec", String(routingHitsWindowSec));
      }
      const res = await api(`/api/v1/routing/hits?${params.toString()}`);
      setRoutingHits(Array.isArray(res.items) ? res.items : []);
      setRoutingHitsStats(res?.stats && typeof res.stats === "object" ? res.stats : null);
    } catch (err) {
      setRoutingHits([]);
      setRoutingHitsStats(null);
      message.error(`加载命中记录失败: ${err.message}`);
    } finally {
      setRoutingHitsLoading(false);
    }
  }

  async function clearRoutingHits() {
    setRoutingHitsLoading(true);
    try {
      await api("/api/v1/routing/hits/clear", {method: "POST"});
      setRoutingHits([]);
      setRoutingHitsStats(null);
      message.success("命中记录已清空");
    } catch (err) {
      message.error(`清空命中记录失败: ${err.message}`);
    } finally {
      setRoutingHitsLoading(false);
    }
  }

  function parseTextLines(raw) {
    return String(raw || "")
      .split("\n")
      .map((x) => x.trim())
      .filter((x) => x && !x.startsWith("#"));
  }

  async function saveMITMConfig() {
    const values = await mitmForm.validateFields();
    const hosts = parseTextLines(values.mitm_hosts);
    const urlReject = parseTextLines(values.mitm_url_reject);
    const doHHosts = parseTextLines(values.mitm_doh_hosts);
    const doTHosts = parseTextLines(values.mitm_dot_hosts);

    setMitmSaving(true);
    try {
      const res = await api("/api/v1/config", {
        method: "PUT",
        body: JSON.stringify({
          mitm: {
            enabled: !!values.mitm_enabled,
            listen: values.mitm_listen || "127.0.0.1:1090",
            hosts,
            url_reject: urlReject,
            doh_dot: {
              enabled: !!values.mitm_doh_dot_enabled,
              doh_hosts: doHHosts,
              dot_hosts: doTHosts,
            }
          }
        })
      });
      setConfig(res.config || config);
      setCurrent(res.current || current);
      message.success(values.mitm_enabled ? "MITM 配置已保存并生效" : "MITM 已关闭");
      await refreshStatus();
    } catch (err) {
      message.error(`保存 MITM 配置失败: ${err.message}`);
    } finally {
      setMitmSaving(false);
    }
  }

  async function downloadMITMCA() {
    setMitmDownloading(true);
    try {
      const headers = {};
      const saved = loadSavedAuth();
      if (saved) {
        headers.Authorization = toBasicAuth(saved.username, saved.password);
      }
      const res = await fetch("/api/v1/mitm/ca", {headers});
      if (res.status === 401 && typeof window !== "undefined") {
        window.dispatchEvent(new Event("anytls-auth-unauthorized"));
      }
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        const text = await res.text();
        if (text) {
          try {
            const parsed = JSON.parse(text);
            errMsg = parsed.error || text;
          } catch {
            errMsg = text;
          }
        }
        throw new Error(errMsg);
      }

      const blob = await res.blob();
      const downloadURL = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadURL;
      a.download = "anytls-mitm-ca.crt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadURL);
      message.success("CA 证书下载成功");
    } catch (err) {
      message.error(`下载 CA 失败: ${err.message}`);
    } finally {
      setMitmDownloading(false);
    }
  }

  function buildMITMInstallCommand() {
    const statusOS = String(runtimeStatus?.os || "").trim().toLowerCase();
    let controlAddr = String(runtimeStatus?.active_control || config?.control || "127.0.0.1:18990").trim();
    if (!controlAddr.includes("://")) {
      if (controlAddr.startsWith("0.0.0.0:")) {
        controlAddr = `127.0.0.1:${controlAddr.split(":").pop()}`;
      } else if (controlAddr.startsWith("[::]:")) {
        controlAddr = `[::1]:${controlAddr.replace(/^\[::\]:/, "")}`;
      } else if (controlAddr.startsWith(":")) {
        controlAddr = `127.0.0.1${controlAddr}`;
      }
    }
    const installEndpoint = controlAddr.includes("://")
      ? `${controlAddr.replace(/\/+$/, "")}/api/v1/mitm/ca/install.sh`
      : `http://${controlAddr}/api/v1/mitm/ca/install.sh`;
    const quotedInstallEndpoint = shellQuoteSingle(installEndpoint);
    const saved = loadSavedAuth();
    const authPart = saved ? `--user ${shellQuoteSingle(`${saved.username}:${saved.password}`)} ` : "";

    if (statusOS === "windows") {
      const certEndpoint = controlAddr.includes("://")
        ? `${controlAddr.replace(/\/+$/, "")}/api/v1/mitm/ca`
        : `http://${controlAddr}/api/v1/mitm/ca`;
      const quotedEndpoint = shellQuoteSingle(certEndpoint);
      return `# 在 PowerShell 中运行
$u = ${quotedEndpoint}
$name = Read-Host "API 用户名（留空表示无认证）"
if ([string]::IsNullOrWhiteSpace($name)) {
  Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile "$env:TEMP\\anytls-mitm-ca.crt"
} else {
  $pwd = Read-Host "API 密码" -AsSecureString
  $cred = New-Object System.Management.Automation.PSCredential($name, $pwd)
  Invoke-WebRequest -UseBasicParsing -Uri $u -Credential $cred -OutFile "$env:TEMP\\anytls-mitm-ca.crt"
}
Import-Certificate -FilePath "$env:TEMP\\anytls-mitm-ca.crt" -CertStoreLocation Cert:\\LocalMachine\\Root`;
    }
    return `curl -fsSL ${authPart}${quotedInstallEndpoint} -o /tmp/anytls-install-mitm-ca.sh && sh /tmp/anytls-install-mitm-ca.sh`;
  }

  async function copyMITMInstallCommand() {
    setMitmCopyingCommand(true);
    try {
      const cmd = buildMITMInstallCommand();
      await copyTextToClipboard(cmd);
      message.success("MITM CA 一键安装命令已复制到剪贴板");
    } catch (err) {
      message.error(`复制安装命令失败: ${err.message}`);
    } finally {
      setMitmCopyingCommand(false);
    }
  }

  function ensureTunTaskIdle(actionName) {
    if (!tunTaskBusy) {
      return true;
    }
    const name = String(actionName || "执行该操作").trim() || "执行该操作";
    message.warning(`TUN 任务执行中，请稍后再${name}`);
    return false;
  }

  async function applyTunToggle(enabled) {
    setTunApplying(true);
    try {
      const submitAt = Date.now();
      setTunTaskProgress({
        status: "pending",
        message: "正在提交 TUN 切换请求...",
        _logs: appendTunStepLog([], "正在提交 TUN 切换请求...", submitAt),
      });
      const values = configForm.getFieldsValue();
      const tunNameDefault = runtimeStatus?.os === "darwin" ? "utun" : "anytls0";
      const res = await api("/api/v1/config", {
        method: "PUT",
        timeoutMS: TUN_TOGGLE_REQUEST_TIMEOUT_MS,
        body: JSON.stringify({
          tun: {
            enabled: !!enabled,
            name: values.tun_name || tunNameDefault,
            mtu: values.tun_mtu || 1500,
            address: values.tun_address || "198.18.0.1/15",
            auto_route: !!values.tun_auto_route,
            disable_other_proxies: !!values.tun_disable_other_proxies,
          }
        })
      });
      const tunTaskID = String(res?.tun_task_id || "").trim();
      if (tunTaskID) {
        const nowMS = Date.now();
        setTunTaskProgress((prev) => ({
          id: tunTaskID,
          status: "pending",
          message: "TUN 任务已入队，等待执行...",
          queue_position: 0,
          queue_total: 0,
          queue_eta_seconds: 0,
          elapsed_seconds: 0,
          _enqueued_at_ms: nowMS,
          _fallback_eta_seconds: 45,
          _logs: appendTunStepLog(prev?._logs, "TUN 任务已入队，等待执行...", nowMS),
        }));
        setTunProgressTick(nowMS);
        await waitTaskDone(tunTaskID, {
          onProgress: (task) => {
            setTunTaskProgress((prev) => ({
              id: tunTaskID,
              status: String(task?.status || "pending").toLowerCase(),
              message: task?.message || "",
              error: task?.error || "",
              queue_position: toPositiveInt(task?.queue_position),
              queue_total: toPositiveInt(task?.queue_total),
              queue_eta_seconds: toPositiveInt(task?.queue_eta_seconds),
              elapsed_seconds: toPositiveInt(task?.elapsed_seconds),
              _enqueued_at_ms: toPositiveInt(prev?._enqueued_at_ms) || Date.now(),
              _fallback_eta_seconds: toPositiveInt(prev?._fallback_eta_seconds) || 45,
              _logs: appendTunStepLog(prev?._logs, task?.message, Date.now()),
            }));
            setTunProgressTick(Date.now());
          },
        });
      }
      setConfig(res.config || config);
      setCurrent(res.current || current);
      setTunTaskProgress((prev) => ({
        id: tunTaskID || "",
        status: "success",
        message: enabled ? "TUN 已开启并生效" : "TUN 已关闭并生效",
        _logs: appendTunStepLog(prev?._logs, enabled ? "TUN 已开启并生效" : "TUN 已关闭并生效", Date.now()),
      }));
      message.success(enabled ? "TUN 已开启，开始接管全局流量" : "TUN 已关闭，已恢复普通网络");
    } catch (err) {
      setTunTaskProgress((prev) => ({
        status: "failed",
        message: "TUN 切换失败",
        error: err.message,
        _logs: appendTunStepLog(prev?._logs, `TUN 切换失败: ${err.message}`, Date.now()),
      }));
      message.error(`TUN 切换失败: ${err.message}`);
    } finally {
      setTunApplying(false);
      void refreshAll();
    }
  }

  async function importNode() {
    const values = await importForm.validateFields();
    setSavingNode(true);
    try {
      await api("/api/v1/nodes/import", {
        method: "POST",
        body: JSON.stringify({
          name: values.name || "",
          uri: values.uri
        })
      });
      importForm.resetFields();
      message.success("导入成功");
      await refreshAll();
    } catch (err) {
      message.error(`导入失败: ${err.message}`);
    } finally {
      setSavingNode(false);
    }
  }

  async function createNode() {
    const values = await manualForm.validateFields();
    setSavingNode(true);
    try {
      await api("/api/v1/nodes", {
        method: "POST",
        body: JSON.stringify({
          name: values.name,
          server: values.server,
          password: values.password,
          sni: values.sni || "",
          egress_ip: values.egress_ip || "",
          egress_rule: values.egress_rule || "",
          groups: normalizeGroupValues(values.groups),
        })
      });
      manualForm.resetFields();
      message.success("新增成功");
      await refreshAll();
    } catch (err) {
      message.error(`新增失败: ${err.message}`);
    } finally {
      setSavingNode(false);
    }
  }

  async function switchNode(name) {
    try {
      await api("/api/v1/switch", {
        method: "POST",
        body: JSON.stringify({name})
      });
      message.success(`已切换到 ${name}`);
      await refreshAll();
    } catch (err) {
      message.error(`切换失败: ${err.message}`);
    }
  }

  function openGroupManage() {
    const firstGroup = groupOptions[0]?.value || "";
    groupRenameForm.setFieldsValue({
      source_group: firstGroup,
      target_group: "",
    });
    groupRemoveForm.setFieldsValue({
      group: firstGroup,
    });
    setGroupManageVisible(true);
  }

  async function applyNodeGroupUpdates(updates, successMessage) {
    const list = Array.isArray(updates) ? updates : [];
    if (list.length === 0) {
      message.warning("没有需要更新的节点");
      return false;
    }
    setGroupManaging(true);
    const failed = [];
    try {
      for (const item of list) {
        const name = String(item?.name || "").trim();
        if (!name) {
          continue;
        }
        const groups = normalizeGroupValues(item.groups);
        try {
          await api(`/api/v1/nodes/${encodeURIComponent(name)}`, {
            method: "PUT",
            body: JSON.stringify({groups})
          });
        } catch (err) {
          failed.push(`${name}: ${err.message}`);
        }
      }

      if (failed.length > 0) {
        Modal.error({
          title: "分组批量更新失败",
          content: failed.join("; "),
        });
        return false;
      }

      message.success(successMessage || "分组更新成功");
      await refreshAll();
      return true;
    } finally {
      setGroupManaging(false);
    }
  }

  async function submitGroupRenameMerge() {
    const values = await groupRenameForm.validateFields();
    const source = String(values.source_group || "").trim();
    const target = String(values.target_group || "").trim();
    if (!source) {
      message.error("请选择来源分组");
      return;
    }
    if (!target) {
      message.error("请输入目标分组");
      return;
    }
    if (source === target) {
      message.warning("来源分组和目标分组相同，无需处理");
      return;
    }
    const sourceNodes = (groupNodeMap[source] || []).slice();
    if (sourceNodes.length === 0) {
      message.warning(`分组 ${source} 下没有节点`);
      return;
    }

    const updates = sourceNodes.map((node) => {
      const next = normalizeGroupValues((node.groups || []).map((g) => (String(g || "").trim() === source ? target : g)));
      return {name: node.name, groups: next};
    });
    const ok = await applyNodeGroupUpdates(updates, `已将 ${sourceNodes.length} 个节点从 ${source} 合并到 ${target}`);
    if (ok) {
      groupRenameForm.setFieldsValue({
        source_group: target,
        target_group: "",
      });
    }
  }

  async function submitGroupRemove() {
    const values = await groupRemoveForm.validateFields();
    const group = String(values.group || "").trim();
    if (!group) {
      message.error("请选择要移除的分组");
      return;
    }
    const sourceNodes = (groupNodeMap[group] || []).slice();
    if (sourceNodes.length === 0) {
      message.warning(`分组 ${group} 下没有节点`);
      return;
    }
    const updates = sourceNodes.map((node) => ({
      name: node.name,
      groups: normalizeGroupValues((node.groups || []).filter((g) => String(g || "").trim() !== group)),
    }));
    const ok = await applyNodeGroupUpdates(updates, `已从 ${sourceNodes.length} 个节点中移除分组 ${group}`);
    if (ok) {
      groupRemoveForm.setFieldsValue({group: ""});
    }
  }

  async function exportNodesByGroup(format) {
    const group = String(nodeGroupAction || "").trim();
    if (!group) {
      message.error("请先选择分组");
      return;
    }
    const targetFormat = format === "json" ? "json" : "text";
    try {
      const res = await api(`/api/v1/nodes/export?group=${encodeURIComponent(group)}&format=${targetFormat}`);
      const count = Number(res.count || 0);
      if (count <= 0) {
        message.warning(`分组 ${group} 下没有可导出节点`);
        return;
      }
      const stamp = new Date().toISOString().replaceAll(":", "-");
      if (targetFormat === "json") {
        downloadReport(`anytls-nodes-${group}-${stamp}.json`, JSON.stringify(res.items || [], null, 2), "application/json;charset=utf-8");
      } else {
        downloadReport(`anytls-nodes-${group}-${stamp}.txt`, String(res.text || ""), "text/plain;charset=utf-8");
      }
      message.success(`已导出 ${count} 个节点（${group}）`);
    } catch (err) {
      message.error(`导出失败: ${err.message}`);
    }
  }

  async function deleteNode(name) {
    try {
      await api(`/api/v1/nodes/${encodeURIComponent(name)}`, {method: "DELETE"});
      message.success(`已删除 ${name}`);
      await refreshAll();
    } catch (err) {
      message.error(`删除失败: ${err.message}`);
    }
  }

  async function deleteSelectedNodes() {
    const targetNames = Array.from(new Set((visibleSelected || []).map((x) => String(x || "").trim()).filter(Boolean)));
    if (targetNames.length === 0) {
      message.warning("请先选择要删除的节点");
      return;
    }
    setBatchDeletingNode(true);
    const failed = [];
    let deleted = 0;
    try {
      for (const name of targetNames) {
        try {
          await api(`/api/v1/nodes/${encodeURIComponent(name)}`, {method: "DELETE"});
          deleted += 1;
        } catch (err) {
          failed.push(`${name}: ${err.message}`);
        }
      }
      if (deleted > 0) {
        message.success(`已删除 ${deleted} 个节点`);
      }
      if (failed.length > 0) {
        Modal.error({
          title: "批量删除部分失败",
          content: failed.join("; "),
        });
      }
      setSelected((prev) => (prev || []).filter((name) => !targetNames.includes(name)));
      await refreshAll();
    } finally {
      setBatchDeletingNode(false);
    }
  }

  function setNodeSelected(name, checked) {
    const target = String(name || "").trim();
    if (!target) {
      return;
    }
    setSelected((prev) => {
      const nextSet = new Set((prev || []).map((x) => String(x || "").trim()).filter(Boolean));
      if (checked) {
        nextSet.add(target);
      } else {
        nextSet.delete(target);
      }
      return Array.from(nextSet);
    });
  }

  function selectAllVisibleNodes() {
    const visibleNames = (nodes || []).map((n) => n.name);
    setSelected((prev) => {
      const next = new Set(prev || []);
      visibleNames.forEach((name) => {
        if (name) {
          next.add(name);
        }
      });
      return Array.from(next);
    });
  }

  function clearVisibleSelectedNodes() {
    const visibleSet = new Set((nodes || []).map((n) => n.name));
    setSelected((prev) => (prev || []).filter((name) => !visibleSet.has(name)));
  }

  function openEdit(node) {
    setEditNodeName(node.name);
    editForm.setFieldsValue({
      server: node.server,
      password: node.password,
      sni: node.sni || "",
      egress_ip: node.egress_ip || "",
      egress_rule: node.egress_rule || "",
      groups: Array.isArray(node.groups) ? node.groups : [],
    });
    setEditVisible(true);
  }

  async function saveNodeEdit() {
    const values = await editForm.validateFields();
    try {
      const payload = {
        server: values.server || "",
        password: values.password || "",
        sni: values.sni || "",
        egress_ip: values.egress_ip || "",
        egress_rule: values.egress_rule || "",
        groups: normalizeGroupValues(values.groups),
      };
      await api(`/api/v1/nodes/${encodeURIComponent(editNodeName)}`, {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      setEditVisible(false);
      message.success("修改成功");
      await refreshAll();
    } catch (err) {
      message.error(`修改失败: ${err.message}`);
    }
  }

  async function runLatency(names) {
    if (latencyTask.running || bandwidthTask.running) {
      message.warning("已有测速任务在执行，请稍候");
      return;
    }
    const pv = probeForm.getFieldsValue();
    const targetNames = Array.from(new Set((names || []).filter(Boolean))).sort((a, b) => {
      const ai = Number.isInteger(nodeOrderMap[a]) ? nodeOrderMap[a] : Number.MAX_SAFE_INTEGER;
      const bi = Number.isInteger(nodeOrderMap[b]) ? nodeOrderMap[b] : Number.MAX_SAFE_INTEGER;
      if (ai !== bi) {
        return ai - bi;
      }
      return String(a).localeCompare(String(b));
    });
    if (targetNames.length === 0) {
      return;
    }
    const failed = [];
    setLatencyTask({running: true, current: 0, total: targetNames.length});
    try {
      for (let i = 0; i < targetNames.length; i += 1) {
        const name = targetNames[i];
        setLatencyTask({running: true, current: i + 1, total: targetNames.length});
        setLatencyLoading((prev) => ({...prev, [name]: true}));
        try {
          const res = await api("/api/v1/test/latency", {
            method: "POST",
            body: JSON.stringify({
              names: [name],
              target: pv.latency_target || "",
              count: pv.latency_count || 3,
              timeout_ms: clampProbeTimeoutMS(pv.latency_timeout_ms)
            })
          });
          const item = Array.isArray(res.results) ? res.results[0] : null;
          if (!item) {
            setLatencyResult((prev) => ({...prev, [name]: "-"}));
            continue;
          }
          if (item.error) {
            setLatencyResult((prev) => ({...prev, [name]: "失败"}));
            failed.push(`${name}: ${item.error}`);
          } else if (item.avg_ms) {
            setLatencyResult((prev) => ({...prev, [name]: `${item.avg_ms.toFixed(2)} ms`}));
          } else {
            setLatencyResult((prev) => ({...prev, [name]: "-"}));
          }
        } catch (err) {
          setLatencyResult((prev) => ({...prev, [name]: "失败"}));
          failed.push(`${name}: ${err.message || err}`);
        } finally {
          setLatencyLoading((prev) => ({...prev, [name]: false}));
        }
      }
      if (failed.length > 0) {
        Modal.error({
          title: "延迟测速失败",
          content: failed.join("; "),
        });
      }
    } catch (err) {
      message.error(`延迟测试失败: ${err.message}`);
    } finally {
      setLatencyTask({running: false, current: 0, total: 0});
      setLatencyLoading((prev) => {
        const next = {...prev};
        targetNames.forEach((n) => { next[n] = false; });
        return next;
      });
    }
  }

  async function runBandwidth(names) {
    if (latencyTask.running || bandwidthTask.running) {
      message.warning("已有测速任务在执行，请稍候");
      return;
    }
    const pv = probeForm.getFieldsValue();
    const targetNames = Array.from(new Set((names || []).filter(Boolean))).sort((a, b) => {
      const ai = Number.isInteger(nodeOrderMap[a]) ? nodeOrderMap[a] : Number.MAX_SAFE_INTEGER;
      const bi = Number.isInteger(nodeOrderMap[b]) ? nodeOrderMap[b] : Number.MAX_SAFE_INTEGER;
      if (ai !== bi) {
        return ai - bi;
      }
      return String(a).localeCompare(String(b));
    });
    if (targetNames.length === 0) {
      return;
    }
    const failed = [];
    setBandwidthTask({running: true, current: 0, total: targetNames.length});
    try {
      for (let i = 0; i < targetNames.length; i += 1) {
        const name = targetNames[i];
        setBandwidthTask({running: true, current: i + 1, total: targetNames.length});
        setBandwidthLoading((prev) => ({...prev, [name]: true}));
        try {
          const res = await api("/api/v1/test/bandwidth", {
            method: "POST",
            body: JSON.stringify({
              names: [name],
              url: pv.bandwidth_url || "",
              max_bytes: pv.max_bytes || 5242880,
              timeout_ms: clampProbeTimeoutMS(pv.bandwidth_timeout_ms)
            })
          });
          const item = Array.isArray(res.results) ? res.results[0] : null;
          if (!item) {
            setBandwidthResult((prev) => ({...prev, [name]: "-"}));
            continue;
          }
          if (item.error) {
            setBandwidthResult((prev) => ({...prev, [name]: "失败"}));
            failed.push(`${name}: ${item.error}`);
          } else if (item.mbps) {
            setBandwidthResult((prev) => ({...prev, [name]: `${item.mbps.toFixed(2)} Mbps`}));
          } else {
            setBandwidthResult((prev) => ({...prev, [name]: "-"}));
          }
        } catch (err) {
          setBandwidthResult((prev) => ({...prev, [name]: "失败"}));
          failed.push(`${name}: ${err.message || err}`);
        } finally {
          setBandwidthLoading((prev) => ({...prev, [name]: false}));
        }
      }
      if (failed.length > 0) {
        Modal.error({
          title: "带宽测速失败",
          content: failed.join("; "),
        });
      }
    } catch (err) {
      message.error(`带宽测试失败: ${err.message}`);
    } finally {
      setBandwidthTask({running: false, current: 0, total: 0});
      setBandwidthLoading((prev) => {
        const next = {...prev};
        targetNames.forEach((n) => { next[n] = false; });
        return next;
      });
    }
  }

  function probeBatchButtonText(base, task) {
    if (!task?.running || !task?.total) {
      return base;
    }
    return `${base} (${task.current}/${task.total})`;
  }

  function parseLatencyMS(value) {
    const text = String(value || "").trim();
    if (!text) {
      return NaN;
    }
    const matched = text.match(/([0-9]+(?:\.[0-9]+)?)/);
    if (!matched) {
      return NaN;
    }
    return Number(matched[1]);
  }

  function latencyButtonText(name) {
    if (latencyLoading[name]) {
      return "...";
    }
    const raw = String(latencyResult[name] || "").trim();
    if (!raw) {
      return "未测";
    }
    if (raw === "失败") {
      return "失败";
    }
    const ms = parseLatencyMS(raw);
    if (Number.isFinite(ms) && ms >= 2000) {
      return "不可用";
    }
    return raw;
  }

  function latencyButtonStyle(name) {
    if (latencyLoading[name]) {
      return undefined;
    }
    const raw = String(latencyResult[name] || "").trim();
    if (!raw) {
      return undefined;
    }
    if (raw === "失败") {
      return {color: "#ff4d4f", borderColor: "#ff4d4f"};
    }
    const ms = parseLatencyMS(raw);
    if (!Number.isFinite(ms)) {
      return undefined;
    }
    if (ms < 200) {
      return {color: "#52c41a", borderColor: "#52c41a"};
    }
    if (ms < 500) {
      return {color: "#fa8c16", borderColor: "#fa8c16"};
    }
    if (ms < 2000) {
      return {color: "#ff4d4f", borderColor: "#ff4d4f"};
    }
    return {color: "#8c8c8c", borderColor: "#8c8c8c"};
  }

  function bandwidthButtonText(name) {
    if (bandwidthLoading[name]) {
      return "...";
    }
    const raw = String(bandwidthResult[name] || "").trim();
    return raw || "未测";
  }

  function bandwidthButtonStyle(name) {
    if (bandwidthLoading[name]) {
      return undefined;
    }
    const raw = String(bandwidthResult[name] || "").trim();
    if (raw === "失败") {
      return {color: "#ff4d4f", borderColor: "#ff4d4f"};
    }
    return undefined;
  }

  async function runDiagnose() {
    if (!ensureTunTaskIdle("运行诊断")) {
      return;
    }
    setDiagnosing(true);
    try {
      const taskID = await createAsyncTask("diagnose");
      const task = await waitTaskDone(taskID);
      const res = task?.result || {};
      const checks = (res.checks || []).map((x, i) => ({
        key: `${x.name}-${i}`,
        name: x.name,
        ok: !!x.ok,
        detail: x.detail || "",
        latency: x.latency_ms || 0,
        error: x.error || ""
      }));
      setDiagnoseRows(checks);
      setDiagnoseSummary(res.summary || null);
      setDiagnoseRaw(res || null);
      setDiagnoseVisible(true);
      await loadTaskCenter();
    } catch (err) {
      message.error(`诊断失败: ${err.message}`);
    } finally {
      setDiagnosing(false);
    }
  }

  async function runRouteCheck() {
    if (!ensureTunTaskIdle("执行路由自检")) {
      return;
    }
    setRouteCheckLoading(true);
    try {
      const taskID = await createAsyncTask("route_check");
      const task = await waitTaskDone(taskID);
      const res = task?.result || {};
      setRouteCheckRaw(res || null);
      setRouteCheckVisible(true);
      await loadTaskCenter();
    } catch (err) {
      message.error(`路由自检失败: ${err.message}`);
    } finally {
      setRouteCheckLoading(false);
    }
  }

  async function runTunCheck() {
    if (!ensureTunTaskIdle("执行 TUN 连通性测试")) {
      return;
    }
    setTunCheckLoading(true);
    let activeTaskID = "";
    try {
      const submitAt = Date.now();
      setTunCheckProgress({
        status: "pending",
        message: "正在提交 TUN 连通性测试任务...",
        _logs: appendTunStepLog([], "正在提交 TUN 连通性测试任务...", submitAt),
      });
      const taskID = await createAsyncTask("tun_check");
      activeTaskID = taskID;
      const nowMS = Date.now();
      setTunCheckProgress((prev) => ({
        id: taskID,
        status: "pending",
        message: "TUN 测试任务已入队，等待执行...",
        queue_position: 0,
        queue_total: 0,
        queue_eta_seconds: 0,
        elapsed_seconds: 0,
        _enqueued_at_ms: nowMS,
        _fallback_eta_seconds: 45,
        _logs: appendTunStepLog(prev?._logs, "TUN 测试任务已入队，等待执行...", nowMS),
      }));
      setTunProgressTick(nowMS);
      const task = await waitTaskDone(taskID, {
        timeoutMS: TUN_TOGGLE_TASK_TIMEOUT_MS,
        onProgress: (progress) => {
          setTunCheckProgress((prev) => ({
            id: taskID,
            status: String(progress?.status || "pending").toLowerCase(),
            message: progress?.message || "",
            error: progress?.error || "",
            queue_position: toPositiveInt(progress?.queue_position),
            queue_total: toPositiveInt(progress?.queue_total),
            queue_eta_seconds: toPositiveInt(progress?.queue_eta_seconds),
            elapsed_seconds: toPositiveInt(progress?.elapsed_seconds),
            _enqueued_at_ms: toPositiveInt(prev?._enqueued_at_ms) || Date.now(),
            _fallback_eta_seconds: toPositiveInt(prev?._fallback_eta_seconds) || 45,
            _logs: appendTunStepLog(prev?._logs, progress?.message, Date.now()),
          }));
          setTunProgressTick(Date.now());
        },
      });
      const res = task?.result || {};
      const isOK = !!res?.summary?.ok;
      setTunCheckRaw(res);
      setTunCheckVisible(true);
      setTunCheckProgress((prev) => ({
        id: taskID,
        status: isOK ? "success" : "issues",
        message: isOK ? "TUN 连通性测试通过" : "TUN 连通性测试发现问题",
        error: "",
        _logs: appendTunStepLog(prev?._logs, isOK ? "TUN 连通性测试通过" : "TUN 连通性测试发现问题", Date.now()),
      }));
      if (isOK) {
        message.success("TUN 连通性测试通过");
      } else {
        message.warning(`TUN 连通性测试发现 ${toPositiveInt(res?.summary?.issue_count)} 个问题`);
      }
      await loadTaskCenter();
    } catch (err) {
      const timeoutTask = err?.task;
      let timeoutResult = timeoutTask?.result && typeof timeoutTask.result === "object" ? timeoutTask.result : null;
      if (!timeoutResult && activeTaskID) {
        try {
          const latest = await api(`/api/v1/tasks/${encodeURIComponent(activeTaskID)}`, {timeoutMS: 6000});
          timeoutResult = latest?.result && typeof latest.result === "object" ? latest.result : null;
        } catch (_) {
        }
      }
      if (timeoutResult) {
        setTunCheckRaw(timeoutResult);
        setTunCheckVisible(true);
      }
      setTunCheckProgress((prev) => ({
        status: "failed",
        message: "TUN 连通性测试失败",
        error: err.message,
        _logs: appendTunStepLog(prev?._logs, `TUN 连通性测试失败: ${err.message}`, Date.now()),
      }));
      message.error(`TUN 连通性测试失败: ${err.message}`);
    } finally {
      setTunCheckLoading(false);
    }
  }

  async function loadRouteSelfHeal() {
    setRouteSelfHealLoading(true);
    try {
      const res = await api("/api/v1/route/selfheal");
      setRouteSelfHealRaw(res || null);
    } catch (err) {
      message.error(`加载路由自愈状态失败: ${err.message}`);
    } finally {
      setRouteSelfHealLoading(false);
    }
  }

  async function runTunCheckTaskForReport() {
    const taskID = await createAsyncTask("tun_check");
    const task = await waitTaskDone(taskID, {timeoutMS: TUN_TOGGLE_TASK_TIMEOUT_MS});
    const res = task?.result || {};
    setTunCheckRaw(res || null);
    return res;
  }

  async function repairOpenWrtDNSFromTunCheck() {
    setTunDNSRepairLoading(true);
    try {
      const res = await api("/api/v1/openwrt/dns/repair", {
        method: "POST",
      });
      const removedAddress = toPositiveInt(res?.address_removed);
      const removedHosts = toPositiveInt(res?.hosts_removed);
      if (res?.ok) {
        message.success(`DNS 修复完成: address移除=${removedAddress}, hosts移除=${removedHosts}`);
      } else {
        const issues = Array.isArray(res?.issues) ? res.issues.join("; ") : "";
        message.warning(`DNS 修复完成但存在告警: ${issues || "请查看日志"}`);
      }
      await refreshStatus();
      await loadRouteSelfHeal();
      await runTunCheck();
    } catch (err) {
      message.error(`DNS 修复失败: ${err.message}`);
    } finally {
      setTunDNSRepairLoading(false);
    }
  }

  async function ensureTunCheckForReport() {
    if (tunCheckRaw && typeof tunCheckRaw === "object") {
      return tunCheckRaw;
    }
    return await runTunCheckTaskForReport();
  }

  function buildSelfHealFullReport(tunCheckSnapshot) {
    return {
      generated_at: new Date().toISOString(),
      runtime_status: runtimeStatus || null,
      route_selfheal: routeSelfHealRaw || null,
      tun_check: tunCheckSnapshot || null,
      diagnose: diagnoseRaw || null,
      route_check: routeCheckRaw || null,
    };
  }

  function downloadReport(filename, content, mimeType) {
    const blob = new Blob([content], {type: mimeType || "text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function exportDiagnoseJSON() {
    if (!diagnoseRaw) {
      message.warning("暂无诊断数据");
      return;
    }
    const stamp = new Date().toISOString().replaceAll(":", "-");
    downloadReport(`anytls-diagnose-${stamp}.json`, JSON.stringify(diagnoseRaw, null, 2), "application/json;charset=utf-8");
  }

  function exportDiagnoseText() {
    if (!diagnoseRaw) {
      message.warning("暂无诊断数据");
      return;
    }
    const lines = [];
    lines.push("AnyTLS Client Diagnose Report");
    lines.push(`Time: ${formatDateTimeCST(diagnoseRaw.time)}`);
    lines.push(`Current: ${diagnoseRaw.current || "-"}`);
    lines.push(`Summary: ok=${diagnoseSummary?.ok ? "true" : "false"}, failed=${diagnoseSummary?.failed || 0}, total=${diagnoseSummary?.total || 0}`);
    lines.push("");
    (diagnoseRaw.checks || []).forEach((c) => {
      const latency = c.latency_ms ? ` latency=${c.latency_ms}ms` : "";
      const detail = c.detail ? ` detail=${c.detail}` : "";
      const err = c.error ? ` error=${c.error}` : "";
      lines.push(`- ${c.name}: ${c.ok ? "OK" : "FAIL"}${latency}${detail}${err}`);
    });
    lines.push("");
    const stamp = new Date().toISOString().replaceAll(":", "-");
    downloadReport(`anytls-diagnose-${stamp}.txt`, lines.join("\\n"), "text/plain;charset=utf-8");
  }

  function exportRouteSelfHealJSON() {
    if (!routeSelfHealRaw) {
      message.warning("暂无路由自愈数据");
      return;
    }
    const stamp = new Date().toISOString().replaceAll(":", "-");
    downloadReport(`anytls-route-selfheal-${stamp}.json`, JSON.stringify(routeSelfHealRaw, null, 2), "application/json;charset=utf-8");
  }

  function exportRouteSelfHealText() {
    if (!routeSelfHealRaw) {
      message.warning("暂无路由自愈数据");
      return;
    }
    const lines = [];
    lines.push("AnyTLS Client Route Self-Heal Report");
    lines.push(`Time: ${formatDateTimeCST(routeSelfHealRaw.time)}`);
    lines.push(`System: ${routeSelfHealRaw.os || "-"} / ${routeSelfHealRaw.arch || "-"}`);
    lines.push(`TUN: ${routeSelfHealRaw?.tun?.running ? "running" : "stopped"} (${routeSelfHealRaw?.tun?.name || "-"}) auto_route=${routeSelfHealRaw?.tun?.auto_route ? "on" : "off"}`);
    lines.push(`Bypass: node ${routeSelfHealRaw?.bypass?.node_success || 0}/${routeSelfHealRaw?.bypass?.node_total || 0}, dns ${routeSelfHealRaw?.bypass?.dns_success || 0}/${routeSelfHealRaw?.bypass?.dns_total || 0}`);
    lines.push(`Default Route: ${routeSelfHealRaw?.route?.default_v4?.output || "-"}`);
    lines.push(`Default Device: ${routeSelfHealRaw?.route?.default_v4?.device || "-"}${routeSelfHealRaw?.route?.default_v4?.via ? ` via ${routeSelfHealRaw.route.default_v4.via}` : ""}`);
    lines.push(`Split 0.0.0.0/1: present=${routeSelfHealRaw?.route?.split_v4?.route_0_1?.present ? "yes" : "no"} on_tun=${routeSelfHealRaw?.route?.split_v4?.route_0_1?.on_tun ? "yes" : "no"}`);
    lines.push(`Split 128.0.0.0/1: present=${routeSelfHealRaw?.route?.split_v4?.route_128_1?.present ? "yes" : "no"} on_tun=${routeSelfHealRaw?.route?.split_v4?.route_128_1?.on_tun ? "yes" : "no"}`);
    lines.push(`Health: ${routeSelfHealRaw?.health?.ok === false ? "risk" : "ok"}`);
    if ((routeSelfHealRaw?.health?.issues || []).length > 0) {
      lines.push("Issues:");
      (routeSelfHealRaw.health.issues || []).forEach((issue) => {
        lines.push(`- ${issue}`);
      });
    }
    lines.push("");
    lines.push("Recent Self-Heal Events:");
    const recent = routeSelfHealRaw?.self_heal?.recent || [];
    if (recent.length === 0) {
      lines.push("- (none)");
    } else {
      recent.forEach((item) => {
        lines.push(`- [${formatDateTimeCST(item.time)}] ${String(item.level || "-").toUpperCase()} ${item.action || "-"} | ${item.detail || "-"}`);
      });
    }
    const stamp = new Date().toISOString().replaceAll(":", "-");
    downloadReport(`anytls-route-selfheal-${stamp}.txt`, lines.join("\\n"), "text/plain;charset=utf-8");
  }

  async function exportFullSelfHealReportJSON() {
    if (!routeSelfHealRaw) {
      message.warning("暂无路由自愈数据");
      return;
    }
    setExportingSelfHealReport(true);
    try {
      const tunCheckSnapshot = await ensureTunCheckForReport();
      const report = buildSelfHealFullReport(tunCheckSnapshot);
      const stamp = new Date().toISOString().replaceAll(":", "-");
      downloadReport(`anytls-full-route-report-${stamp}.json`, JSON.stringify(report, null, 2), "application/json;charset=utf-8");
      message.success("完整诊断报告已导出(JSON)");
    } catch (err) {
      message.error(`导出完整报告失败: ${err.message}`);
    } finally {
      setExportingSelfHealReport(false);
    }
  }

  async function exportFullSelfHealReportText() {
    if (!routeSelfHealRaw) {
      message.warning("暂无路由自愈数据");
      return;
    }
    setExportingSelfHealReport(true);
    try {
      const tunCheckSnapshot = await ensureTunCheckForReport();
      const report = buildSelfHealFullReport(tunCheckSnapshot);
      const lines = [];
      lines.push("AnyTLS Full Route Self-Heal Report");
      lines.push(`Generated: ${formatDateTimeCST(report.generated_at)}`);
      lines.push(`Current Node: ${runtimeStatus?.current || current || "-"}`);
      lines.push(`TUN: ${runtimeStatus?.tun?.running ? "running" : "stopped"} / enabled=${runtimeStatus?.tun?.enabled ? "true" : "false"}`);
      lines.push("");

      const healHealth = routeSelfHealRaw?.health || {};
      lines.push(`[Route Self-Heal] ok=${healHealth?.ok ? "true" : "false"} issues=${(healHealth?.issues || []).length}`);
      (healHealth?.issues || []).forEach((item) => {
        lines.push(`- ${item}`);
      });
      lines.push("");

      const tunSummary = tunCheckSnapshot?.summary || {};
      lines.push(`[TUN Check] ok=${tunSummary?.ok ? "true" : "false"} issue_count=${toPositiveInt(tunSummary?.issue_count)} failed_steps=${toPositiveInt(tunSummary?.failed_steps)}/${toPositiveInt(tunSummary?.total_steps)}`);
      (tunCheckSnapshot?.issues || []).forEach((item) => {
        lines.push(`- ${item}`);
      });
      lines.push("");

      lines.push("[TUN Check Steps]");
      (tunCheckSnapshot?.steps || []).forEach((step) => {
        const name = String(step?.name || "-");
        const status = String(step?.status || "-");
        const duration = `${toPositiveInt(step?.duration_ms)}ms`;
        const msg = String(step?.message || "").trim();
        const err = String(step?.error || "").trim();
        lines.push(`- ${name} [${status}] ${duration}${msg ? ` | ${msg}` : ""}${err ? ` | err=${err}` : ""}`);
      });
      lines.push("");

      const stamp = new Date().toISOString().replaceAll(":", "-");
      downloadReport(`anytls-full-route-report-${stamp}.txt`, lines.join("\n"), "text/plain;charset=utf-8");
      message.success("完整诊断报告已导出(文本)");
    } catch (err) {
      message.error(`导出完整报告失败: ${err.message}`);
    } finally {
      setExportingSelfHealReport(false);
    }
  }

  async function loadBackups() {
    setBackupLoading(true);
    try {
      const res = await api("/api/v1/config/backups");
      const rows = (res.backups || []).map((x) => ({
        key: x.name,
        name: x.name,
        size: x.size || 0,
        mod_time: x.mod_time || "",
      }));
      setBackupRows(rows);
      setBackupVisible(true);
    } catch (err) {
      message.error(`加载备份失败: ${err.message}`);
    } finally {
      setBackupLoading(false);
    }
  }

  async function rollbackBackup(name) {
    setRollingBack(true);
    try {
      const res = await api("/api/v1/config/rollback", {
        method: "POST",
        body: JSON.stringify({backup: name || ""})
      });
      message.success(res.message || "回滚成功，请重启 API 完整生效");
      await refreshAll();
      await loadBackups();
    } catch (err) {
      message.error(`回滚失败: ${err.message}`);
    } finally {
      setRollingBack(false);
    }
  }

  async function loadLogs() {
    setLogLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", String(logLimit || 300));
      if (logCurrentNodeOnly) {
        params.set("level", "error");
      } else if (logLevel) {
        params.set("level", logLevel);
      }
      if (logSearch) {
        params.set("search", logSearch);
      }
      const res = await api(`/api/v1/logs?${params.toString()}`);
      let items = Array.isArray(res.items) ? res.items : [];
      if (logCurrentNodeOnly) {
        const nodeName = String(current || "").trim().toLowerCase();
        const nodeServer = String(currentNode?.server || "").trim().toLowerCase();
        const nodeHost = nodeServer.includes(":") ? nodeServer.slice(0, nodeServer.lastIndexOf(":")).replace(/^\[|\]$/g, "") : nodeServer;
        items = items.filter((item) => {
          const level = String(item?.level || "").toLowerCase();
          if (!(level === "error" || level === "fatal")) {
            return false;
          }
          const msg = String(item?.message || "").toLowerCase();
          if (!msg) {
            return false;
          }
          if (nodeName && msg.includes(nodeName)) {
            return true;
          }
          if (nodeServer && msg.includes(nodeServer)) {
            return true;
          }
          if (nodeHost && msg.includes(nodeHost)) {
            return true;
          }
          return false;
        });
      }
      setLogs(items);
    } catch (err) {
      message.error(`加载日志失败: ${err.message}`);
    } finally {
      setLogLoading(false);
    }
  }

  async function clearLogs() {
    setLogLoading(true);
    try {
      await api("/api/v1/logs/clear", {method: "POST"});
      setLogs([]);
      message.success("日志已清空");
    } catch (err) {
      message.error(`清空日志失败: ${err.message}`);
    } finally {
      setLogLoading(false);
    }
  }

  async function loadSubscriptions() {
    setSubscriptionLoading(true);
    try {
      const res = await api("/api/v1/subscriptions");
      setSubscriptions(res.items || []);
    } catch (err) {
      message.error(`加载订阅失败: ${err.message}`);
    } finally {
      setSubscriptionLoading(false);
    }
  }

  async function loadTaskCenter(options = {}) {
    const {silent = false} = options;
    if (taskCenterLoadingRef.current) {
      return;
    }
    taskCenterLoadingRef.current = true;
    setTaskCenterLoading(true);
    try {
      const res = await api("/api/v1/tasks?limit=200");
      setTaskCenterItems(Array.isArray(res.items) ? res.items : []);
      setTaskCenterQueue(res && typeof res.queue === "object" ? res.queue : null);
    } catch (err) {
      const msg = String(err?.message || "");
      const transient = msg.includes("请求超时") || msg.includes("Failed to fetch") || msg.includes("NetworkError") || msg.includes("task not found");
      if (!(silent && transient) && !transient) {
        message.error(`加载任务中心失败: ${err.message}`);
      }
    } finally {
      setTaskCenterLoading(false);
      taskCenterLoadingRef.current = false;
    }
  }

  function openCreateSubscription() {
    setEditingSubscriptionID("");
    subscriptionForm.resetFields();
    subscriptionForm.setFieldsValue({
      enabled: true,
      update_interval_sec: 3600,
      node_prefix: "",
      groups: []
    });
    setSubscriptionModalVisible(true);
  }

  function openEditSubscription(item) {
    setEditingSubscriptionID(item.id);
    subscriptionForm.setFieldsValue({
      id: item.id,
      name: item.name,
      url: item.url,
      enabled: !!item.enabled,
      update_interval_sec: item.update_interval_sec || 3600,
      node_prefix: item.node_prefix || "",
      groups: Array.isArray(item.groups) ? item.groups : []
    });
    setSubscriptionModalVisible(true);
  }

  async function saveSubscription() {
    const values = await subscriptionForm.validateFields();
    const payload = {
      id: (values.id || "").trim(),
      name: (values.name || "").trim(),
      url: (values.url || "").trim(),
      enabled: !!values.enabled,
      update_interval_sec: values.update_interval_sec || 3600,
      node_prefix: (values.node_prefix || "").trim(),
      groups: normalizeGroupValues(values.groups)
    };
    setSubscriptionSaving(true);
    try {
      if (editingSubscriptionID) {
        await api(`/api/v1/subscriptions/${encodeURIComponent(editingSubscriptionID)}`, {
          method: "PUT",
          body: JSON.stringify({
            name: payload.name,
            url: payload.url,
            enabled: payload.enabled,
            update_interval_sec: payload.update_interval_sec,
            node_prefix: payload.node_prefix,
            groups: payload.groups,
          })
        });
      } else {
        await api("/api/v1/subscriptions", {
          method: "POST",
          body: JSON.stringify(payload)
        });
      }
      setSubscriptionModalVisible(false);
      await loadSubscriptions();
      message.success(editingSubscriptionID ? "订阅已更新" : "订阅已新增");
    } catch (err) {
      message.error(`保存订阅失败: ${err.message}`);
    } finally {
      setSubscriptionSaving(false);
    }
  }

  async function deleteSubscription(id) {
    setSubscriptionLoading(true);
    try {
      await api(`/api/v1/subscriptions/${encodeURIComponent(id)}`, {
        method: "DELETE"
      });
      await loadSubscriptions();
      await refreshAll();
      message.success("订阅已删除");
    } catch (err) {
      message.error(`删除订阅失败: ${err.message}`);
    } finally {
      setSubscriptionLoading(false);
    }
  }

  const subscriptionUpdating = subscriptionUpdatingAll || Object.keys(subscriptionUpdatingIDs).length > 0;

  async function updateSubscriptionNow(id) {
    if (!ensureTunTaskIdle("更新订阅")) {
      return;
    }
    if (id) {
      setSubscriptionUpdatingIDs((prev) => ({...prev, [id]: true}));
    } else {
      setSubscriptionUpdatingAll(true);
    }
    try {
      const taskID = await createAsyncTask("subscription_update", {id: id || ""});
      const task = await waitTaskDone(taskID);
      const res = task?.result || {};
      const failed = Number(res.failed || 0);
      if (failed > 0) {
        const failedItems = (res.results || []).filter((x) => x.error);
        Modal.error({
          title: "订阅更新失败",
          content: failedItems.map((x) => `${x.name || x.id}: ${x.error}`).join("; "),
        });
      } else {
        message.success("订阅更新完成");
      }
      await loadSubscriptions();
      await loadTaskCenter();
      await refreshAll();
    } catch (err) {
      message.error(`订阅更新失败: ${err.message}`);
    } finally {
      if (id) {
        setSubscriptionUpdatingIDs((prev) => {
          const next = {...prev};
          delete next[id];
          return next;
        });
      } else {
        setSubscriptionUpdatingAll(false);
      }
    }
  }

  useEffect(() => {
    if (!loggedIn || activeTab !== "logs") {
      return undefined;
    }
    loadLogs();
    if (!logAutoRefresh) {
      return undefined;
    }
    const timer = setInterval(() => {
      loadLogs();
    }, 3000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab, logAutoRefresh, logLevel, logSearch, logLimit, logCurrentNodeOnly, current, currentNode]);

  useEffect(() => {
    if (!loggedIn || activeTab !== "subscriptions") {
      return undefined;
    }
    loadSubscriptions();
    const timer = setInterval(() => {
      loadSubscriptions();
    }, 20000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab]);

  useEffect(() => {
    if (!loggedIn || activeTab !== "tasks") {
      return undefined;
    }
    loadTaskCenter({silent: false});
    if (!taskCenterAutoRefresh) {
      return undefined;
    }
    const timer = setInterval(() => {
      loadTaskCenter({silent: true});
    }, 3000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab, taskCenterAutoRefresh]);

  useEffect(() => {
    const status = String(tunTaskProgress?.status || "").toLowerCase();
    if (status !== "pending" && status !== "running") {
      return undefined;
    }
    const timer = setInterval(() => {
      setTunProgressTick(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, [tunTaskProgress?.status]);

  useEffect(() => {
    if (!loggedIn || activeTab !== "routing") {
      return undefined;
    }
    loadRoutingProviders();
    const timer = setInterval(() => {
      loadRoutingProviders();
    }, 15000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab]);

  useEffect(() => {
    if (!loggedIn || activeTab !== "routing_hits") {
      return undefined;
    }
    loadRoutingHits();
    if (!routingHitsAutoRefresh) {
      return undefined;
    }
    const timer = setInterval(() => {
      loadRoutingHits();
    }, 3000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab, routingHitsAutoRefresh, routingHitsLimit, routingHitsAction, routingHitsNetwork, routingHitsSource, routingHitsSourceClient, routingHitsSearch, routingHitsNode, routingHitsRule, routingHitsWindowSec]);

  useEffect(() => {
    if (!loggedIn || activeTab !== "route_selfheal") {
      return undefined;
    }
    loadRouteSelfHeal();
    const timer = setInterval(() => {
      loadRouteSelfHeal();
    }, 5000);
    return () => clearInterval(timer);
  }, [loggedIn, activeTab]);

  if (booting) {
    return (
      <Layout>
        <div className="login-page">
          <Card className="login-card">
            <Typography.Title level={3} style={{marginTop: 0}}>AnyTLS Client</Typography.Title>
            <Typography.Text type="secondary">正在连接本地 API ...</Typography.Text>
          </Card>
        </div>
      </Layout>
    );
  }

  if (!loggedIn) {
    return (
      <Layout>
        <div className="login-page">
          <Card className="login-card" title="登录 AnyTLS Client">
            <Form form={loginForm} layout="vertical" onFinish={submitLogin}>
              <Form.Item name="username" label="用户名" rules={[{required: true, message: "请输入用户名"}]}>
                <Input autoComplete="username" />
              </Form.Item>
              <Form.Item name="password" label="密码" rules={[{required: true, message: "请输入密码"}]}>
                <Input.Password autoComplete="current-password" />
              </Form.Item>
              <Form.Item>
                <Checkbox checked={rememberAuth} onChange={(e) => setRememberAuth(e.target.checked)}>
                  记住账号密码
                </Checkbox>
              </Form.Item>
              {loginError ? (
                <Alert style={{marginBottom: 12}} type="error" showIcon message={loginError} />
              ) : null}
              <Button type="primary" htmlType="submit" block loading={loginLoading}>
                登录
              </Button>
            </Form>
          </Card>
        </div>
      </Layout>
    );
  }

  function nodePrimaryActionLabel(section) {
    if (!section || section.key === "__ungrouped__") {
      return "切换";
    }
    return "设为本组出口";
  }

  function isSectionEgressNode(section, nodeName) {
    if (!section || section.key === "__ungrouped__") {
      return false;
    }
    const group = String(section.group || "").trim();
    const name = String(nodeName || "").trim();
    if (!group || !name) {
      return false;
    }
    return String(routingGroupEgress?.[group] || "").trim() === name;
  }

  async function handleNodePrimaryAction(section, record) {
    if (!record?.name) {
      return;
    }
    if (!section || section.key === "__ungrouped__") {
      await switchNode(record.name);
      return;
    }
    await setGroupEgressAndSave(section.group, record.name);
  }

  function buildNodeColumnsForSection(section) {
    return [
      {
        title: "节点名称",
        dataIndex: "name",
        render: (_, record) => <Typography.Text strong>{record.name}</Typography.Text>
      },
      {title: "协议", dataIndex: "protocol", width: 110, render: () => <Tag color="processing">AnyTLS</Tag>},
      {
        title: "状态",
        dataIndex: "name",
        render: (name) => name === current ? <Tag color="blue">当前</Tag> : <Tag>待机</Tag>
      },
      {
        title: "操作",
        dataIndex: "name",
        render: (_, record) => (
          <Space wrap>
            {isSectionEgressNode(section, record.name) ? (
              <Button
                size="small"
                type="primary"
                style={{background: "#52c41a", borderColor: "#52c41a", color: "#fff", pointerEvents: "none"}}
              >
                出口
              </Button>
            ) : (
              <Button size="small" onClick={() => handleNodePrimaryAction(section, record)}>{nodePrimaryActionLabel(section)}</Button>
            )}
            <Button size="small" onClick={() => openEdit(record)}>修改</Button>
            <Button size="small" style={latencyButtonStyle(record.name)} loading={!!latencyLoading[record.name]} onClick={() => runLatency([record.name])}>{latencyButtonText(record.name)}</Button>
            <Button size="small" style={bandwidthButtonStyle(record.name)} loading={!!bandwidthLoading[record.name]} onClick={() => runBandwidth([record.name])}>{bandwidthButtonText(record.name)}</Button>
            <Popconfirm title={`删除 ${record.name} ?`} onConfirm={() => deleteNode(record.name)}>
              <Button danger size="small">删除</Button>
            </Popconfirm>
          </Space>
        )
      }
    ];
  }

  const groupStatsColumns = [
    {title: "分组", dataIndex: "group"},
    {title: "节点数", dataIndex: "count", width: 120},
    {
      title: "操作",
      dataIndex: "group",
      width: 260,
      render: (group) => (
        <Space wrap>
          <Button
            size="small"
            onClick={() => {
              groupRenameForm.setFieldsValue({source_group: group});
              setGroupManageVisible(true);
            }}
          >
            设为来源
          </Button>
          <Button
            size="small"
            onClick={() => {
              groupRemoveForm.setFieldsValue({group});
              setGroupManageVisible(true);
            }}
          >
            设为移除
          </Button>
        </Space>
      )
    }
  ];

  const logColumns = [
    {title: "时间", dataIndex: "time", width: 210, render: (v) => formatDateTimeCST(v)},
    {
      title: "级别",
      dataIndex: "level",
      width: 90,
      render: (v) => {
        const color = v === "error" || v === "fatal" ? "red" : (v === "warn" || v === "warning" ? "orange" : "blue");
        return <Tag color={color}>{(v || "-").toUpperCase()}</Tag>;
      }
    },
    {title: "内容", dataIndex: "message"}
  ];

  const taskCenterColumns = [
    {title: "时间", dataIndex: "created_at", width: 170, render: (v) => formatDateTimeCST(v)},
    {title: "类型", dataIndex: "kind", width: 160, render: (v) => <Tag>{String(v || "-")}</Tag>},
    {
      title: "状态",
      dataIndex: "status",
      width: 100,
      render: (v) => {
        const status = String(v || "").toLowerCase();
        const color = status === "success"
          ? "green"
          : status === "failed"
            ? "red"
            : status === "running"
              ? "processing"
              : "default";
        const label = status === "success"
          ? "成功"
          : status === "failed"
            ? "失败"
            : status === "running"
              ? "执行中"
              : "排队中";
        return <Tag color={color}>{label}</Tag>;
      }
    },
    {
      title: "队列/预计",
      dataIndex: "queue_position",
      width: 220,
      render: (_, item) => {
        const text = formatTaskQueueSummary(item);
        return (
          <Typography.Text ellipsis={{tooltip: text}} style={{display: "inline-block", maxWidth: "100%"}}>
            {text}
          </Typography.Text>
        );
      }
    },
    {title: "消息", dataIndex: "message", width: 200, ellipsis: true},
    {
      title: "错误",
      dataIndex: "error",
      width: 280,
      ellipsis: true,
      render: (v) => {
        const text = String(v || "-");
        return (
          <Typography.Text
            type={text === "-" ? undefined : "danger"}
            ellipsis={{tooltip: text}}
            style={{display: "inline-block", maxWidth: "100%"}}
          >
            {text}
          </Typography.Text>
        );
      }
    },
    {
      title: "耗时",
      dataIndex: "elapsed_seconds",
      width: 120,
      render: (_, item) => formatTaskElapsedSummary(item) || "-"
    },
    {title: "完成时间", dataIndex: "finished_at", width: 170, render: (v) => formatDateTimeCST(v)},
  ];

  const subscriptionColumns = [
    {title: "名称", dataIndex: "name", width: 110, ellipsis: true},
    {
      title: "URL",
      dataIndex: "url",
      width: 420,
      ellipsis: true,
      render: (v) => {
        const text = String(v || "");
        return (
          <Typography.Text
            copyable={text ? {text} : false}
            ellipsis={{tooltip: text || "-"}}
            style={{display: "inline-block", maxWidth: "100%"}}
          >
            {text || "-"}
          </Typography.Text>
        );
      }
    },
    {title: "状态", dataIndex: "enabled", width: 64, render: (v) => v ? <Tag color="blue">启用</Tag> : <Tag>停用</Tag>},
    {
      title: "分组",
      dataIndex: "groups",
      width: 108,
      render: (groups) => Array.isArray(groups) && groups.length > 0 ? (
        <Space size={[4, 4]} wrap>
          {groups.map((g) => <Tag key={g}>{g}</Tag>)}
        </Space>
      ) : "-"
    },
    {title: "识别格式", dataIndex: ["status", "result", "source_format"], width: 86, render: (v) => v ? <Tag color="processing">{v}</Tag> : "-"},
    {
      title: "解析摘要",
      dataIndex: ["status", "result", "parse_summary"],
      width: 260,
      ellipsis: true,
      render: (v) => {
        const text = formatSubscriptionParseSummary(v);
        return (
          <Typography.Text ellipsis={{tooltip: text}} style={{display: "inline-block", maxWidth: "100%"}}>
            {text}
          </Typography.Text>
        );
      }
    },
    {title: "间隔(s)", dataIndex: "update_interval_sec", width: 72},
    {title: "上次成功", dataIndex: ["status", "last_success_at"], width: 150, render: (v) => formatDateTimeCST(v)},
    {
      title: "最近错误",
      dataIndex: ["status", "error"],
      width: 150,
      ellipsis: true,
      render: (v) => {
        const text = String(v || "-");
        return (
          <Typography.Text ellipsis={{tooltip: text}} style={{display: "inline-block", maxWidth: "100%"}}>
            {text}
          </Typography.Text>
        );
      }
    },
    {
      title: "操作",
      dataIndex: "id",
      width: 180,
      render: (_, item) => (
        <Space size={6}>
          <Button size="small" onClick={() => openEditSubscription(item)}>编辑</Button>
          <Button size="small" loading={!!subscriptionUpdatingIDs[item.id]} disabled={tunTaskBusy || subscriptionUpdatingAll} onClick={() => updateSubscriptionNow(item.id)}>手动更新</Button>
          <Popconfirm title={`删除订阅 ${item.name} ?`} onConfirm={() => deleteSubscription(item.id)}>
            <Button size="small" danger>删除</Button>
          </Popconfirm>
        </Space>
      )
    }
  ];

  const routingRuleColumns = [
    {title: "#", dataIndex: "index", width: 60, render: (v) => v + 1},
    {
      title: "类型",
      dataIndex: "rule",
      width: 170,
      render: (rule) => {
        const parsed = parseRoutingRuleToForm(rule);
        return parsed.rule_type === "ADVANCED" ? "高级(手写)" : parsed.rule_type;
      }
    },
    {
      title: "动作",
      dataIndex: "rule",
      width: 170,
      render: (rule) => {
        const parsed = parseRoutingRuleToForm(rule);
        return formatRoutingActionLabel(parsed.action_kind, parsed.action_node, parsed.action_group);
      }
    },
    {title: "规则内容", dataIndex: "rule"},
    {
      title: "操作",
      dataIndex: "index",
      width: 180,
      render: (_, row) => (
        <Space>
          <Button size="small" onClick={() => openEditRoutingRule(row.index)}>编辑</Button>
          <Popconfirm title="确认删除该规则？" onConfirm={() => deleteRoutingRule(row.index)}>
            <Button size="small" danger>删除</Button>
          </Popconfirm>
        </Space>
      )
    }
  ];

  const routingProviderColumns = [
    {title: "名称", dataIndex: "name", width: 180},
    {title: "类型", dataIndex: "type", width: 90},
    {title: "行为", dataIndex: "behavior", width: 110, render: (v) => v || "auto"},
    {title: "格式", dataIndex: "format", width: 100, render: (v, row) => row.is_geoip ? "mmdb" : "auto"},
    {
      title: "来源",
      dataIndex: "url",
      width: 420,
      ellipsis: true,
      render: (_, row) => {
        const text = row.type === "http" ? (row.url || "-") : (row.path || "-");
        return (
          <Typography.Text
            copyable={text && text !== "-" ? {text} : false}
            ellipsis={{tooltip: text || "-"}}
            style={{display: "inline-block", maxWidth: "100%"}}
          >
            {text || "-"}
          </Typography.Text>
        );
      }
    },
    {title: "间隔(s)", dataIndex: "interval_sec", width: 110, render: (v, row) => row.auto_update ? (v || 3600) : "-"},
    {title: "状态", dataIndex: "updating", width: 110, render: (v, row) => row.auto_update ? (v ? <Tag color="processing">更新中</Tag> : <Tag color={row.error ? "red" : "blue"}>{row.error ? "异常" : "正常"}</Tag>) : <Tag>手动</Tag>},
    {title: "上次成功", dataIndex: "last_success", width: 190, render: (v) => formatDateTimeCST(v)},
    {
      title: "操作",
      dataIndex: "provider_name",
      width: 240,
      render: (name, row) => (
        <Space wrap>
          <Button size="small" onClick={() => openEditRoutingProvider(name)}>编辑</Button>
          {row.auto_update ? (
            <Button
              size="small"
              loading={!!routingUpdatingNames[String(name || "").trim()]}
              disabled={tunTaskBusy || routingUpdatingAll}
              onClick={() => updateSingleRoutingProvider(name)}
            >
              更新
            </Button>
          ) : null}
          {!row.is_geoip ? (
            <Popconfirm title={`删除规则集 ${name} ?`} onConfirm={() => deleteRoutingProvider(name)}>
              <Button size="small" danger>删除</Button>
            </Popconfirm>
          ) : null}
        </Space>
      )
    }
  ];

  const routingHitColumns = [
    {title: "时间", dataIndex: "time", width: 210, render: (v) => formatDateTimeCST(v)},
    {title: "来源", dataIndex: "source", width: 90, render: (v) => v === "test" ? <Tag color="gold">测试</Tag> : <Tag color="blue">实时</Tag>},
    {title: "客户端来源", dataIndex: "source_client", width: 170, render: (v) => String(v || "").trim() || "-"},
    {title: "网络", dataIndex: "network", width: 90, render: (v) => (v || "-").toUpperCase()},
    {title: "目标", dataIndex: "destination", width: 260},
    {title: "动作", dataIndex: "action", width: 100, render: (v) => <Tag color={v === "REJECT" ? "red" : (v === "DIRECT" ? "green" : "processing")}>{v || "-"}</Tag>},
    {title: "节点", dataIndex: "node", width: 130, render: (v) => v || "-"},
    {title: "命中规则", dataIndex: "rule"},
  ];

  const mitmURLRejectRuleColumns = [
    {title: "规则", dataIndex: "rule", ellipsis: true},
    {title: "命中数", dataIndex: "hits", width: 100},
    {title: "最近命中", dataIndex: "last_hit_at", width: 190, render: (v) => formatDateTimeCST(v)},
  ];

  const routeSelfHealEventColumns = [
    {title: "时间", dataIndex: "time", width: 200, render: (v) => formatDateTimeCST(v)},
    {
      title: "级别",
      dataIndex: "level",
      width: 90,
      render: (v) => {
        const level = String(v || "").toLowerCase();
        const color = level === "warn" || level === "warning"
          ? "orange"
          : (level === "error" ? "red" : "blue");
        return <Tag color={color}>{String(v || "-").toUpperCase()}</Tag>;
      }
    },
    {title: "动作", dataIndex: "action", width: 180},
    {title: "详情", dataIndex: "detail"},
  ];

  return (
    <Layout>
      <div className="page">
        <div className="page-header">
          <Typography.Title level={3} style={{marginTop: 0, marginBottom: 0}}>AnyTLS Client 管理面板</Typography.Title>
          <Space className="page-header-actions">
            <Button onClick={logout}>退出登录</Button>
            <Button icon={<SettingOutlined />} onClick={() => setConfigVisible(true)}>基础配置</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddNodeVisible(true)}>新增节点</Button>
          </Space>
        </div>
        <Space direction="vertical" style={{display: "flex"}}>
          <Alert type="info" showIcon message={`配置文件: ${configPath || "-"}`} />

          <Card className="card" title="运行状态" extra={<Button size="small" onClick={refreshStatus} loading={statusLoading}>刷新状态</Button>}>
            <Space wrap>
              <Tag color="blue">默认节点: {runtimeStatus?.current || "-"}</Tag>
              <Tag color={runtimeStatus?.tun?.running ? "processing" : "default"}>TUN: {runtimeStatus?.tun?.running ? "运行中" : "未运行"}</Tag>
              {(runtimeStatus?.tun?.enabled && !runtimeStatus?.tun?.running && runtimeStatus?.tun?.auto_recover_running) ? (
                <Tag color="gold">TUN自动恢复: 监测中</Tag>
              ) : null}
              <Tag color={runtimeStatus?.mitm?.running ? "processing" : "default"}>MITM: {runtimeStatus?.mitm?.running ? "运行中" : "未运行"}</Tag>
              <Tag color={runtimeStatus?.mitm?.doh_dot_enabled ? "blue" : "default"}>DoH/DoT MITM: {runtimeStatus?.mitm?.doh_dot_enabled ? "开启" : "关闭"}</Tag>
              <Tag>URL Reject规则: {runtimeStatus?.mitm?.url_reject_count || 0}</Tag>
              <Tag color={(runtimeStatus?.mitm?.url_reject_hit_count || 0) > 0 ? "orange" : "default"}>
                URL Reject命中: {runtimeStatus?.mitm?.url_reject_hit_count || 0}
              </Tag>
              {runtimeStatus?.mitm?.url_reject_last_hit_at ? (
                <Tooltip title={runtimeStatus?.mitm?.url_reject_last_hit_url || "-"}>
                  <Tag color="gold">最近命中: {formatDateTimeCST(runtimeStatus?.mitm?.url_reject_last_hit_at)}</Tag>
                </Tooltip>
              ) : null}
              {runtimeStatus?.mitm?.url_reject_last_hit_rule ? (
                <Tooltip title={runtimeStatus?.mitm?.url_reject_last_hit_rule || "-"}>
                  <Tag color="purple">最近规则: {String(runtimeStatus?.mitm?.url_reject_last_hit_rule || "").slice(0, 28)}</Tag>
                </Tooltip>
              ) : null}
              {Array.isArray(runtimeStatus?.mitm?.url_reject_top_rules) && runtimeStatus?.mitm?.url_reject_top_rules.length > 0 ? (
                <Tooltip
                  title={(runtimeStatus?.mitm?.url_reject_top_rules || [])
                    .map((item) => `${item?.hits || 0}x ${item?.rule || "-"}`)
                    .join("\n")}
                >
                  <Tag color="magenta">
                    Top规则: {(runtimeStatus?.mitm?.url_reject_top_rules?.[0]?.hits || 0)}x
                  </Tag>
                </Tooltip>
              ) : null}
              <Tag color={runtimeStatus?.failover?.enabled ? "blue" : "default"}>故障切换: {runtimeStatus?.failover?.enabled ? "开启" : "关闭"}</Tag>
              <Tag color={runtimeStatus?.failover?.best_latency_enabled ? "green" : "default"}>
                切换策略: {runtimeStatus?.failover?.best_latency_enabled ? "故障后最低延迟" : "顺序切换"}
              </Tag>
              {(runtimeStatus?.failover?.probe_interval_ms || 0) > 0 ? (
                <Tag color={(runtimeStatus?.failover?.probe_interval_scale || 1) > 1 ? "orange" : "default"}>
                  故障探测: {runtimeStatus?.failover?.probe_interval_ms || 0}ms
                  {(runtimeStatus?.failover?.probe_interval_scale || 1) > 1
                    ? ` (x${runtimeStatus?.failover?.probe_interval_scale || 1})`
                    : ""}
                </Tag>
              ) : null}
              <Tag color={runtimeStatus?.routing?.enabled ? "blue" : "default"}>规则分流: {runtimeStatus?.routing?.enabled ? "开启" : "关闭"}</Tag>
              {runtimeStatus?.routing?.recent_node ? (
                <Tooltip title={`${runtimeStatus?.routing?.recent_destination || "-"} · ${runtimeStatus?.routing?.recent_rule || "-"}`}>
                  <Tag color="cyan">最近出口: {runtimeStatus?.routing?.recent_node}</Tag>
                </Tooltip>
              ) : null}
              {runtimeStatus?.routing?.recent_time ? (
                <Tag color="default">最近路由: {formatDateTimeCST(runtimeStatus?.routing?.recent_time)}</Tag>
              ) : null}
              <Tag>DNS映射: {runtimeStatus?.routing?.dns_map_match_count || 0} 条</Tag>
              <Tag>DNS上游: {runtimeStatus?.routing?.dns_upstream_count || 0}</Tag>
              <Tag color={(runtimeStatus?.routing?.dns_query_failure || 0) > 0 ? "red" : "green"}>
                DNS请求: {(runtimeStatus?.routing?.dns_query_success || 0)} 成功 / {(runtimeStatus?.routing?.dns_query_failure || 0)} 失败
              </Tag>
              <Tag color={(runtimeStatus?.bypass?.node_failed || 0) > 0 ? "red" : "green"}>
                节点旁路: {(runtimeStatus?.bypass?.node_success || 0)} / {(runtimeStatus?.bypass?.node_total || 0)}
              </Tag>
              <Tag>监听: {runtimeStatus?.active_listen || "-"}</Tag>
              <Tag>API: {runtimeStatus?.active_control || "-"}</Tag>
              <Tag
                color={
                  (Number(runtimeStatus?.inbound?.soft_limit || runtimeStatus?.inbound?.limit || 0) > 0 &&
                    Number(runtimeStatus?.inbound?.active || 0) >= Number(runtimeStatus?.inbound?.soft_limit || runtimeStatus?.inbound?.limit || 0))
                    ? "red"
                    : "blue"
                }
              >
                入站并发: {runtimeStatus?.inbound?.active ?? 0} / {runtimeStatus?.inbound?.soft_limit ?? runtimeStatus?.inbound?.limit ?? "-"}
              </Tag>
              <Tag>硬上限: {runtimeStatus?.inbound?.limit ?? "-"}</Tag>
              <Tag>入站峰值: {runtimeStatus?.inbound?.peak ?? 0}</Tag>
              <Tag>入站等待: {runtimeStatus?.inbound?.slot_wait_ms ?? "-"}ms</Tag>
              <Tag color={(runtimeStatus?.inbound?.dropped_total || 0) > 0 ? "orange" : "default"}>
                入站丢弃: {runtimeStatus?.inbound?.dropped_total || 0}
              </Tag>
              <Tag color={(runtimeStatus?.inbound?.dropped_pressure_total || 0) > 0 ? "orange" : "default"}>
                压力丢弃: {runtimeStatus?.inbound?.dropped_pressure_total || 0}
              </Tag>
              <Tag color={(runtimeStatus?.inbound?.accept_emfile_total || 0) > 0 ? "red" : "green"}>
                接受EMFILE: {runtimeStatus?.inbound?.accept_emfile_total || 0}
              </Tag>
              {(runtimeStatus?.inbound?.emfile_cooldown_ms || 0) > 0 ? (
                <Tag color="red">EMFILE冷却: {runtimeStatus?.inbound?.emfile_cooldown_ms || 0}ms</Tag>
              ) : null}
              <Tag color={(runtimeStatus?.inbound?.pressure_level || 0) >= 2 ? "orange" : "default"}>
                压力等级: {runtimeStatus?.inbound?.pressure_level || 0}
              </Tag>
              <Tag>
                压力分数: {(((runtimeStatus?.inbound?.pressure_score_x100 || 0) / 100)).toFixed(2)}
              </Tag>
              <Tag>FD占用: {runtimeStatus?.inbound?.fd_usage || "-"}</Tag>
              <Tag>运行时长: {runtimeStatus?.uptime_sec || 0}s</Tag>
              <Tag>版本: {runtimeStatus?.version || "-"}</Tag>
              <Tag>Commit: {shortCommit(runtimeStatus?.commit)}</Tag>
              <Tag>构建时间: {formatBuildTime(runtimeStatus?.build_time)}</Tag>
            </Space>
            {(runtimeStatus?.bypass?.node_failed || 0) > 0 ? (
              <Alert
                style={{marginTop: 12}}
                type="error"
                showIcon
                message={`节点旁路失败: ${runtimeStatus?.bypass?.node_failed || 0} 个`}
                description={Array.isArray(runtimeStatus?.bypass?.failed_targets) ? runtimeStatus.bypass.failed_targets.join("; ") : "-"}
              />
            ) : null}
            {runtimeStatus?.health?.ok === false ? (
              <Alert
                style={{marginTop: 12}}
                type="error"
                showIcon
                message="运行状态异常"
                description={(runtimeStatus.health.issues || []).join("; ")}
              />
            ) : null}
            {(runtimeStatus?.tun?.enabled && !runtimeStatus?.tun?.running && runtimeStatus?.tun?.auto_recover_running && runtimeStatus?.tun?.auto_recover_last_error) ? (
              <Alert
                style={{marginTop: 12}}
                type="warning"
                showIcon
                message="TUN 自动恢复监测中"
                description={runtimeStatus?.tun?.auto_recover_last_error}
              />
            ) : null}
          </Card>
          <Card className="card">
            <Tabs
              activeKey={activeTab}
              onChange={setActiveTab}
              items={[
                {
                  key: "nodes",
                  label: "节点管理",
                  children: (
                    <>
                      <Form form={probeForm} layout="inline" initialValues={{
                        latency_target: "1.1.1.1:443",
                        latency_count: 3,
                        latency_timeout_ms: 2000,
                        egress_probe_target: DEFAULT_EGRESS_PROBE_TARGET,
                        bandwidth_url: "https://speed.cloudflare.com/__down?bytes=5000000",
                        max_bytes: 5242880,
                        bandwidth_timeout_ms: 2000
                      }}>
                        <Form.Item name="latency_target" label="延迟目标"><Input style={{width: 180}} /></Form.Item>
                        <Form.Item name="latency_count" label="次数"><InputNumber min={1} max={10} /></Form.Item>
                        <Form.Item name="latency_timeout_ms" label="延迟超时(ms)"><InputNumber min={200} max={2000} /></Form.Item>
                        <Form.Item name="egress_probe_target" label="出口验证 URL"><Input style={{width: 320}} /></Form.Item>
                        <Form.Item name="bandwidth_url" label="测速 URL"><Input style={{width: 360}} /></Form.Item>
                        <Form.Item name="max_bytes" label="测速字节"><InputNumber min={262144} max={209715200} /></Form.Item>
                        <Form.Item name="bandwidth_timeout_ms" label="带宽超时(ms)"><InputNumber min={200} max={2000} /></Form.Item>
                      </Form>
                      <Divider />
                      <Space style={{marginBottom: 12}} wrap>
                        <Select
                          allowClear
                          value={nodeGroupAction || undefined}
                          onChange={(v) => setNodeGroupAction(v || "")}
                          style={{width: 240}}
                          options={groupOptions}
                          placeholder="选择分组执行批量操作"
                        />
                        <Tag>组节点数: {groupActionNodes.length}</Tag>
                        <Tag color={selectedGroupEgressNode ? "processing" : "default"}>
                          当前分组出口: {selectedGroupEgressNode || "-"}
                        </Tag>
                        <Button
                          loading={egressProbeLoading}
                          disabled={latencyTask.running || bandwidthTask.running}
                          onClick={() => runEgressQuickProbe("", selectedGroupEgressNode || "", false)}
                        >
                          出口验证
                        </Button>
                        {egressProbeResult ? (
                          <Tag color={egressProbeResult?.ok ? "success" : "error"}>
                            出口探测: {egressProbeResult?.ok ? "成功" : "失败"}
                            {String(egressProbeResult?.node || "").trim() ? ` · ${String(egressProbeResult?.node || "").trim()}` : ""}
                            {Number(egressProbeResult?.status_code || 0) > 0 ? ` · HTTP ${Number(egressProbeResult?.status_code || 0)}` : ""}
                          </Tag>
                        ) : null}
                        {egressProbeResult?.time ? (
                          <Tag>探测时间: {formatDateTimeCST(egressProbeResult?.time)}</Tag>
                        ) : null}
                        <Button
                          loading={latencyTask.running && latencyTask.total === groupActionNodes.length && latencyTask.total > 0}
                          disabled={groupActionNodes.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runLatency(groupActionNodes.map((n) => n.name))}
                        >
                          {probeBatchButtonText("按组测延迟", latencyTask)}
                        </Button>
                        <Button
                          loading={bandwidthTask.running && bandwidthTask.total === groupActionNodes.length && bandwidthTask.total > 0}
                          disabled={groupActionNodes.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runBandwidth(groupActionNodes.map((n) => n.name))}
                        >
                          {probeBatchButtonText("按组测带宽", bandwidthTask)}
                        </Button>
                        <Button disabled={!nodeGroupAction} onClick={() => exportNodesByGroup("text")}>导出组 TXT</Button>
                        <Button disabled={!nodeGroupAction} onClick={() => exportNodesByGroup("json")}>导出组 JSON</Button>
                        <Button onClick={openGroupManage}>分组管理</Button>
                      </Space>
                      <Alert
                        style={{marginBottom: 12}}
                        type="info"
                        showIcon
                        message="每个分组单独成列表。点击节点右侧“设为本组出口”会立即保存；该节点成为出口后按钮会变为绿色“出口”。"
                      />
                      <Space style={{marginBottom: 12}} wrap>
                        <Button type="primary" onClick={() => setAddNodeVisible(true)}>新增节点</Button>
                        <Button
                          loading={latencyTask.running && latencyTask.total === nodes.length && latencyTask.total > 0}
                          disabled={nodes.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runLatency(nodes.map((n) => n.name))}
                        >
                          {probeBatchButtonText("全量测延迟", latencyTask)}
                        </Button>
                        <Button
                          loading={bandwidthTask.running && bandwidthTask.total === nodes.length && bandwidthTask.total > 0}
                          disabled={nodes.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runBandwidth(nodes.map((n) => n.name))}
                        >
                          {probeBatchButtonText("全量测带宽", bandwidthTask)}
                        </Button>
                        <Button
                          loading={latencyTask.running && latencyTask.total === visibleSelected.length && latencyTask.total > 0}
                          disabled={visibleSelected.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runLatency(visibleSelected)}
                        >
                          {probeBatchButtonText("批量测延迟", latencyTask)}
                        </Button>
                        <Button
                          loading={bandwidthTask.running && bandwidthTask.total === visibleSelected.length && bandwidthTask.total > 0}
                          disabled={visibleSelected.length === 0 || latencyTask.running || bandwidthTask.running}
                          onClick={() => runBandwidth(visibleSelected)}
                        >
                          {probeBatchButtonText("批量测带宽", bandwidthTask)}
                        </Button>
                        <Popconfirm
                          title={`确认删除已选 ${visibleSelected.length} 个节点？`}
                          onConfirm={deleteSelectedNodes}
                          okText="删除"
                          cancelText="取消"
                        >
                          <Button
                            danger
                            loading={batchDeletingNode}
                            disabled={visibleSelected.length === 0 || batchDeletingNode}
                          >
                            批量删除
                          </Button>
                        </Popconfirm>
                      </Space>
                      <Space style={{marginBottom: 10}} wrap>
                        <Button size="small" onClick={selectAllVisibleNodes} disabled={nodes.length === 0}>全选所有节点</Button>
                        <Button size="small" onClick={clearVisibleSelectedNodes} disabled={visibleSelected.length === 0}>取消当前选择</Button>
                        <Tag>已选 {visibleSelected.length}</Tag>
                      </Space>
                      <Space direction="vertical" style={{display: "flex"}}>
                        {(groupedNodeSections || []).map((section) => (
                          <Card
                            key={`node-group-${section.key}`}
                            size="small"
                            title={(
                              <Space wrap>
                                <Typography.Text strong>{section.group}</Typography.Text>
                                <Tag>{section.nodes.length} 节点</Tag>
                              </Space>
                            )}
                          >
                            {section.key === "__ungrouped__" ? (
                              <Typography.Text type="secondary">未参与分组出口映射</Typography.Text>
                            ) : null}
                            {isMobile ? (
                              <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                                {(section.nodes || []).map((record) => (
                                  <Card key={`${section.key}-${record.name}`} size="small">
                                    <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                      <Checkbox
                                        checked={visibleSelected.includes(record.name)}
                                        onChange={(e) => setNodeSelected(record.name, e.target.checked)}
                                      >
                                        <Typography.Text strong>{record.name}</Typography.Text>
                                      </Checkbox>
                                      {record.name === current ? <Tag color="blue">当前</Tag> : <Tag>待机</Tag>}
                                    </Space>
                                    <Space style={{marginTop: 10}} wrap>
                                      {isSectionEgressNode(section, record.name) ? (
                                        <Button
                                          size="small"
                                          type="primary"
                                          style={{background: "#52c41a", borderColor: "#52c41a", color: "#fff", pointerEvents: "none"}}
                                        >
                                          出口
                                        </Button>
                                      ) : (
                                        <Button size="small" onClick={() => handleNodePrimaryAction(section, record)}>{nodePrimaryActionLabel(section)}</Button>
                                      )}
                                      <Button size="small" onClick={() => openEdit(record)}>修改</Button>
                                      <Button size="small" style={latencyButtonStyle(record.name)} loading={!!latencyLoading[record.name]} onClick={() => runLatency([record.name])}>{latencyButtonText(record.name)}</Button>
                                      <Button size="small" style={bandwidthButtonStyle(record.name)} loading={!!bandwidthLoading[record.name]} onClick={() => runBandwidth([record.name])}>{bandwidthButtonText(record.name)}</Button>
                                      <Popconfirm title={`删除 ${record.name} ?`} onConfirm={() => deleteNode(record.name)}>
                                        <Button danger size="small">删除</Button>
                                      </Popconfirm>
                                    </Space>
                                  </Card>
                                ))}
                              </Space>
                            ) : (
                              <Table
                                rowKey="name"
                                loading={loading}
                                dataSource={section.nodes}
                                columns={buildNodeColumnsForSection(section)}
                                pagination={false}
                                rowSelection={{
                                  selectedRowKeys: visibleSelected.filter((name) => (section.nodes || []).some((n) => n.name === name)),
                                  onChange: (keys) => {
                                    const sectionSet = new Set((section.nodes || []).map((n) => n.name));
                                    const normalized = (keys || []).map((k) => String(k || "").trim()).filter(Boolean);
                                    setSelected((prev) => {
                                      const base = (prev || []).filter((name) => !sectionSet.has(name));
                                      return Array.from(new Set([...base, ...normalized]));
                                    });
                                  }
                                }}
                              />
                            )}
                          </Card>
                        ))}
                        {(groupedNodeSections || []).length === 0 ? (
                          <Typography.Text type="secondary">暂无节点</Typography.Text>
                        ) : null}
                      </Space>
                    </>
                  )
                },
                {
                  key: "routing",
                  label: "规则分流",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Button type="primary" loading={routingSaving} onClick={saveRoutingConfig}>保存规则配置</Button>
                        <Button loading={routingUpdatingAll} disabled={tunTaskBusy || routingUpdatingAnyItem} onClick={updateRoutingProvidersNow}>手动更新规则集</Button>
                        <Button onClick={refreshAll} loading={loading}>从运行配置刷新</Button>
                        <Button type="dashed" icon={<PlusOutlined />} onClick={openAddRoutingRule}>新增规则</Button>
                        <Button type="dashed" icon={<PlusOutlined />} onClick={openAddRoutingProvider}>新增规则集</Button>
                      </Space>
                      <Form form={routingForm} layout="vertical">
                        <Form.Item label="启用规则分流" name="routing_enabled" valuePropName="checked">
                          <Switch />
                        </Form.Item>
                        <Form.Item label="默认兜底动作（未命中任意规则时）" required>
                          <Space wrap>
                            <Form.Item name="routing_default_action_kind" noStyle initialValue="group">
                              <Select
                                style={{width: 220}}
                                options={[
                                  {value: "group", label: "按分组出口"},
                                  {value: "direct", label: "DIRECT"},
                                  {value: "reject", label: "REJECT"},
                                ]}
                              />
                            </Form.Item>
                            <Form.Item shouldUpdate={(prev, next) => prev.routing_default_action_kind !== next.routing_default_action_kind} noStyle>
                              {() => {
                                const mode = String(routingForm.getFieldValue("routing_default_action_kind") || "group").toLowerCase();
                                if (mode !== "group") {
                                  return null;
                                }
                                return (
                                  <Form.Item
                                    name="routing_default_action_group"
                                    style={{marginBottom: 0}}
                                    rules={[{required: true, message: "请选择兜底分组"}]}
                                  >
                                    <Select
                                      showSearch
                                      style={{width: 280}}
                                      placeholder={routingActionGroupOptions.length ? "选择分组" : "请先在节点中配置分组"}
                                      options={routingActionGroupOptions}
                                    />
                                  </Form.Item>
                                );
                              }}
                            </Form.Item>
                          </Space>
                        </Form.Item>
                        <Alert
                          type="info"
                          showIcon
                          message="规则与规则集均通过列表管理。规则集格式固定为 auto，会按 URL/文件内容自动识别 mrs/sgmodule/yaml/text。RULE-SET 默认可继承规则集内动作（也可手动覆盖）。GEOIP,XX 规则使用当前配置中的 mmdb 数据，可在规则集列表的 GEOIP(mmdb) 行查看状态并手动更新。分组出口节点请到“节点管理”页按分组设置；未命中规则时将按这里的兜底动作执行。"
                        />
                      </Form>
                      <Divider />
                      <Typography.Title level={5} style={{marginTop: 0}}>规则列表</Typography.Title>
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(routingRules || []).map((rule, index) => {
                            const parsed = parseRoutingRuleToForm(rule);
                            const typeLabel = parsed.rule_type === "ADVANCED" ? "高级(手写)" : parsed.rule_type;
                            const actionLabel = formatRoutingActionLabel(parsed.action_kind, parsed.action_node, parsed.action_group);
                            return (
                              <Card key={`routing-rule-mobile-${index}`} size="small">
                                <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                  <Typography.Text strong>#{index + 1} {typeLabel}</Typography.Text>
                                  <Tag color="processing">{actionLabel}</Tag>
                                </Space>
                                <Typography.Paragraph style={{marginTop: 8, marginBottom: 8}} ellipsis={{rows: 3, tooltip: rule}}>
                                  {rule}
                                </Typography.Paragraph>
                                <Space wrap>
                                  <Button size="small" onClick={() => openEditRoutingRule(index)}>编辑</Button>
                                  <Popconfirm title="确认删除该规则？" onConfirm={() => deleteRoutingRule(index)}>
                                    <Button size="small" danger>删除</Button>
                                  </Popconfirm>
                                </Space>
                              </Card>
                            );
                          })}
                          {(routingRules || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无规则，点击“新增规则”添加</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="index"
                          dataSource={(routingRules || []).map((rule, index) => ({index, rule}))}
                          columns={routingRuleColumns}
                          pagination={false}
                          locale={{emptyText: "暂无规则，点击“新增规则”添加"}}
                        />
                      )}
                      <Divider />
                      <Typography.Title level={5} style={{marginTop: 0}}>规则集列表</Typography.Title>
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(routingProviderRows || []).map((item) => (
                            <Card key={`routing-provider-mobile-${item.name}`} size="small">
                              <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                <Typography.Text strong>{item.name}</Typography.Text>
                                <Tag>{item.type || "http"}</Tag>
                              </Space>
                              <div style={{marginTop: 8}}>
                                <Typography.Text type="secondary">行为: {item.behavior || "auto"}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">格式: {item.is_geoip ? "mmdb" : "auto"}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">来源: {item.type === "http" ? (item.url || "-") : (item.path || "-")}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">状态: {item.auto_update ? (item.error ? "异常" : (item.updating ? "更新中" : "正常")) : "手动"}</Typography.Text>
                              </div>
                              <Space style={{marginTop: 10}} wrap>
                                <Button size="small" onClick={() => openEditRoutingProvider(item.provider_name || item.name)}>编辑</Button>
                                {item.auto_update ? (
                                  <Button
                                    size="small"
                                    loading={!!routingUpdatingNames[String(item.provider_name || item.name || "").trim()]}
                                    disabled={tunTaskBusy || routingUpdatingAll}
                                    onClick={() => updateSingleRoutingProvider(item.provider_name || item.name)}
                                  >
                                    更新
                                  </Button>
                                ) : null}
                                {!item.is_geoip ? (
                                  <Popconfirm title={`删除规则集 ${item.name} ?`} onConfirm={() => deleteRoutingProvider(item.provider_name || item.name)}>
                                    <Button size="small" danger>删除</Button>
                                  </Popconfirm>
                                ) : null}
                              </Space>
                            </Card>
                          ))}
                          {(routingProviderRows || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无规则集，点击“新增规则集”添加</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="key"
                          loading={routingProviderLoading}
                          dataSource={routingProviderRows}
                          columns={routingProviderColumns}
                          tableLayout="fixed"
                          scroll={{x: 1520}}
                          pagination={false}
                          locale={{emptyText: "暂无规则集，点击“新增规则集”添加"}}
                        />
                      )}
                    </>
                  )
                },
                {
                  key: "routing_hits",
                  label: "命中测试",
                  children: (
                    <>
                      <Form
                        form={routingMatchForm}
                        layout="inline"
                        initialValues={{
                          target: "4.ipw.cn:443",
                          network: "tcp",
                          record: true,
                        }}
                      >
                        <Form.Item name="target" label="目标地址" rules={[{required: true, message: "请输入目标地址"}]}>
                          <Input style={{width: 320}} placeholder="example.com:443 / https://example.com" />
                        </Form.Item>
                        <Form.Item name="network" label="网络">
                          <Select style={{width: 120}} options={[{value: "tcp", label: "TCP"}, {value: "udp", label: "UDP"}]} />
                        </Form.Item>
                        <Form.Item name="record" valuePropName="checked">
                          <Checkbox>写入命中记录</Checkbox>
                        </Form.Item>
                        <Form.Item>
                          <Button type="primary" loading={routingMatchLoading} onClick={testRoutingMatch}>执行命中测试</Button>
                        </Form.Item>
                      </Form>
                      {routingMatchResult ? (
                        <Alert
                          style={{marginTop: 12}}
                          type="info"
                          showIcon
                          message={`命中结果: ${routingMatchResult.action || "-"} ${routingMatchResult.node ? `(${routingMatchResult.node})` : ""}`}
                          description={`目标 ${routingMatchResult.destination || "-"} 命中规则: ${routingMatchResult.rule || "-"}`}
                        />
                      ) : null}
                      {Array.isArray(runtimeStatus?.mitm?.url_reject_top_rules) && runtimeStatus?.mitm?.url_reject_top_rules.length > 0 ? (
                        <Card
                          size="small"
                          style={{marginTop: 12}}
                          title="MITM URL Reject 命中统计（Top 规则）"
                          extra={<Tag color="orange">总命中: {runtimeStatus?.mitm?.url_reject_hit_count || 0}</Tag>}
                        >
                          <Table
                            rowKey={(item, idx) => `mitm-url-reject-top-${idx}`}
                            size="small"
                            pagination={false}
                            dataSource={runtimeStatus?.mitm?.url_reject_top_rules || []}
                            columns={mitmURLRejectRuleColumns}
                          />
                        </Card>
                      ) : null}
                      <Divider />
                      {routingHitsStats ? (
                        <Card size="small" style={{marginBottom: 12}} title="命中统计（当前筛选范围）">
                          <Space wrap>
                            <Tag color="blue">命中总数: {routingHitsStats.total_matched || 0}</Tag>
                            <Tag>返回条数: {routingHitsStats.returned || 0}</Tag>
                            <Tag color="orange">DEFAULT: {routingHitsStats.default_rule_hits || 0}</Tag>
                            <Tag color={Number(routingHitsStats.host_resolved_rate || 0) >= 60 ? "green" : "red"}>
                              域名识别率: {formatPercent(routingHitsStats.host_resolved_rate)}
                            </Tag>
                            <Tag>已识别: {routingHitsStats.host_resolved_hits || 0}</Tag>
                            <Tag>未识别: {routingHitsStats.host_unresolved_hits || 0}</Tag>
                          </Space>
                          <Space wrap style={{marginTop: 8}}>
                            <Typography.Text strong>快速过滤:</Typography.Text>
                            {routingHitsAction ? (
                              <Tag closable onClose={() => setRoutingHitsAction("")}>动作={routingHitsAction}</Tag>
                            ) : null}
                            {routingHitsSourceClient ? (
                              <Tag closable onClose={() => setRoutingHitsSourceClient("")}>客户端={routingHitsSourceClient}</Tag>
                            ) : null}
                            {routingHitsNode ? (
                              <Tag closable onClose={() => setRoutingHitsNode("")}>节点={routingHitsNode}</Tag>
                            ) : null}
                            {routingHitsRule ? (
                              <Tag closable onClose={() => setRoutingHitsRule("")}>规则={routingHitsRule}</Tag>
                            ) : null}
                            {Number(routingHitsWindowSec) > 0 ? (
                              <Tag closable onClose={() => setRoutingHitsWindowSec(0)}>窗口={routingHitsWindowSec}s</Tag>
                            ) : null}
                            {!routingHitsAction && !routingHitsSourceClient && !routingHitsNode && !routingHitsRule && Number(routingHitsWindowSec) <= 0 ? (
                              <Tag>无</Tag>
                            ) : null}
                          </Space>
                          <Space wrap style={{marginTop: 8}}>
                            <Typography.Text strong>动作分布:</Typography.Text>
                            {Object.entries(routingHitsStats.actions || {})
                              .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))
                              .map(([name, count]) => (
                                <Tag
                                  key={`hit-action-${name}`}
                                  color={routingHitsAction === name ? "processing" : "default"}
                                  style={{cursor: "pointer"}}
                                  onClick={() => setRoutingHitsAction(routingHitsAction === name ? "" : name)}
                                >
                                  {name}: {count}
                                </Tag>
                              ))}
                          </Space>
                          <Space wrap style={{marginTop: 8}}>
                            <Typography.Text strong>Top 规则:</Typography.Text>
                            {(routingHitsStats.top_rules || []).slice(0, 8).map((item) => {
                              const selected = routingHitsRule === item.name;
                              return (
                                <Tag
                                  key={`hit-rule-${item.name}`}
                                  color={selected ? "processing" : "default"}
                                  style={{cursor: "pointer"}}
                                  onClick={() => setRoutingHitsRule(selected ? "" : item.name)}
                                >
                                  {item.name} ({item.count})
                                </Tag>
                              );
                            })}
                          </Space>
                          <Space wrap style={{marginTop: 8}}>
                            <Typography.Text strong>Top 节点:</Typography.Text>
                            {(routingHitsStats.top_nodes || []).slice(0, 8).map((item) => {
                              const selected = routingHitsNode === item.name;
                              return (
                                <Tag
                                  key={`hit-node-${item.name}`}
                                  color={selected ? "processing" : "default"}
                                  style={{cursor: "pointer"}}
                                  onClick={() => {
                                    setRoutingHitsNode(selected ? "" : item.name);
                                    if (!selected) {
                                      setRoutingHitsAction("NODE");
                                    }
                                  }}
                                >
                                  {item.name} ({item.count})
                                </Tag>
                              );
                            })}
                          </Space>
                          <Space wrap style={{marginTop: 8}}>
                            <Typography.Text strong>Top 客户端:</Typography.Text>
                            {(routingHitsStats.top_clients || []).slice(0, 8).map((item) => {
                              const selected = routingHitsSourceClient === item.name;
                              return (
                                <Tag
                                  key={`hit-client-${item.name}`}
                                  color={selected ? "processing" : "default"}
                                  style={{cursor: "pointer"}}
                                  onClick={() => setRoutingHitsSourceClient(selected ? "" : item.name)}
                                >
                                  {item.name} ({item.count})
                                </Tag>
                              );
                            })}
                          </Space>
                        </Card>
                      ) : null}
                      <Space style={{marginBottom: 12}} wrap>
                        <Select
                          value={routingHitsAction}
                          onChange={setRoutingHitsAction}
                          style={{width: 140}}
                          options={[
                            {value: "", label: "全部动作"},
                            {value: "NODE", label: "NODE"},
                            {value: "DIRECT", label: "DIRECT"},
                            {value: "REJECT", label: "REJECT"},
                            {value: "PROXY", label: "PROXY"},
                          ]}
                        />
                        <Select
                          value={routingHitsNetwork}
                          onChange={setRoutingHitsNetwork}
                          style={{width: 140}}
                          options={[
                            {value: "", label: "全部网络"},
                            {value: "tcp", label: "TCP"},
                            {value: "udp", label: "UDP"},
                          ]}
                        />
                        <Select
                          value={routingHitsSource}
                          onChange={setRoutingHitsSource}
                          style={{width: 140}}
                          options={[
                            {value: "", label: "全部来源"},
                            {value: "live", label: "实时流量"},
                            {value: "test", label: "测试请求"},
                          ]}
                        />
                        <Select
                          showSearch
                          value={routingHitsSourceClient}
                          onChange={setRoutingHitsSourceClient}
                          style={{width: 220}}
                          options={routingHitSourceClientOptions}
                        />
                        <Input
                          placeholder="搜索目标/规则/动作"
                          value={routingHitsSearch}
                          onChange={(e) => setRoutingHitsSearch(e.target.value)}
                          style={{width: 220}}
                        />
                        <Input
                          placeholder="节点过滤(精确)"
                          value={routingHitsNode}
                          onChange={(e) => setRoutingHitsNode(e.target.value)}
                          style={{width: 180}}
                        />
                        <Input
                          placeholder="规则过滤(精确)"
                          value={routingHitsRule}
                          onChange={(e) => setRoutingHitsRule(e.target.value)}
                          style={{width: 220}}
                        />
                        <Select
                          value={routingHitsWindowSec}
                          onChange={(v) => setRoutingHitsWindowSec(Number(v || 0))}
                          style={{width: 150}}
                          options={[
                            {value: 0, label: "时间窗口: 全部"},
                            {value: 60, label: "最近 1 分钟"},
                            {value: 300, label: "最近 5 分钟"},
                            {value: 900, label: "最近 15 分钟"},
                            {value: 3600, label: "最近 60 分钟"},
                          ]}
                        />
                        <InputNumber min={50} max={5000} value={routingHitsLimit} onChange={(v) => setRoutingHitsLimit(v || 300)} />
                        <Checkbox checked={routingHitsAutoRefresh} onChange={(e) => setRoutingHitsAutoRefresh(e.target.checked)}>自动刷新</Checkbox>
                        <Button loading={routingHitsLoading} onClick={loadRoutingHits}>刷新记录</Button>
                        <Button
                          onClick={() => {
                            setRoutingHitsAction("");
                            setRoutingHitsSourceClient("");
                            setRoutingHitsNode("");
                            setRoutingHitsRule("");
                            setRoutingHitsWindowSec(0);
                          }}
                        >
                          清除快速过滤
                        </Button>
                        <Popconfirm title="确认清空命中记录？" onConfirm={clearRoutingHits}>
                          <Button danger loading={routingHitsLoading}>清空记录</Button>
                        </Popconfirm>
                      </Space>
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(routingHits || []).map((item) => (
                            <Card key={`routing-hit-mobile-${item.id}`} size="small">
                              <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                <Typography.Text strong>{formatDateTimeCST(item.time)}</Typography.Text>
                                <Tag color={item.action === "REJECT" ? "red" : (item.action === "DIRECT" ? "green" : "processing")}>{item.action || "-"}</Tag>
                              </Space>
                              <div style={{marginTop: 8}}>
                                <Typography.Text type="secondary">来源: {item.source === "test" ? "测试" : "实时"} / {(item.network || "-").toUpperCase()}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">客户端: {item.source_client || "-"}</Typography.Text>
                                <br />
                                <Typography.Text>目标: {item.destination || "-"}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">节点: {item.node || "-"}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">规则: {item.rule || "-"}</Typography.Text>
                              </div>
                            </Card>
                          ))}
                          {(routingHits || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无命中记录</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="id"
                          loading={routingHitsLoading}
                          dataSource={routingHits}
                          columns={routingHitColumns}
                          pagination={false}
                          scroll={{y: 420}}
                        />
                      )}
                    </>
                  )
                },
                {
                  key: "route_selfheal",
                  label: "路由自愈",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Button loading={routeSelfHealLoading} onClick={loadRouteSelfHeal}>刷新状态</Button>
                        <Button loading={routeCheckLoading} disabled={tunTaskBusy} onClick={runRouteCheck}>路由自检</Button>
                        <Button onClick={exportRouteSelfHealJSON}>导出 JSON</Button>
                        <Button onClick={exportRouteSelfHealText}>导出文本</Button>
                        <Button loading={exportingSelfHealReport} onClick={exportFullSelfHealReportJSON}>导出完整报告(JSON)</Button>
                        <Button loading={exportingSelfHealReport} onClick={exportFullSelfHealReportText}>导出完整报告(文本)</Button>
                      </Space>
                      {routeSelfHealRaw ? (
                        <>
                          <Descriptions size="small" bordered column={isMobile ? 1 : 2} style={{marginBottom: 12}}>
                            <Descriptions.Item label="系统">{routeSelfHealRaw.os || "-"} / {routeSelfHealRaw.arch || "-"}</Descriptions.Item>
                            <Descriptions.Item label="时间">{formatDateTimeCST(routeSelfHealRaw.time)}</Descriptions.Item>
                            <Descriptions.Item label="TUN">
                              <Tag color={routeSelfHealRaw?.tun?.running ? "processing" : "default"}>
                                {routeSelfHealRaw?.tun?.running ? "运行中" : "未运行"}
                              </Tag>
                              <Tag>{routeSelfHealRaw?.tun?.name || "-"}</Tag>
                              <Tag color={routeSelfHealRaw?.tun?.auto_route ? "blue" : "default"}>
                                auto_route: {routeSelfHealRaw?.tun?.auto_route ? "on" : "off"}
                              </Tag>
                            </Descriptions.Item>
                            <Descriptions.Item label="节点旁路">
                              {routeSelfHealRaw?.bypass?.node_success || 0} / {routeSelfHealRaw?.bypass?.node_total || 0}
                              {(routeSelfHealRaw?.bypass?.node_failed || 0) > 0 ? (
                                <Tag color="red" style={{marginLeft: 8}}>失败 {routeSelfHealRaw?.bypass?.node_failed || 0}</Tag>
                              ) : null}
                            </Descriptions.Item>
                            <Descriptions.Item label="默认 IPv4 路由">
                              <Typography.Text code>{routeSelfHealRaw?.route?.default_v4?.output || "-"}</Typography.Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="默认设备">
                              <Tag>{routeSelfHealRaw?.route?.default_v4?.device || "-"}</Tag>
                              {routeSelfHealRaw?.route?.default_v4?.via ? (
                                <Tag color="blue">via {routeSelfHealRaw.route.default_v4.via}</Tag>
                              ) : null}
                            </Descriptions.Item>
                            <Descriptions.Item label="分片路由 0.0.0.0/1">
                              {routeSelfHealRaw?.route?.split_v4?.route_0_1?.present ? (
                                <Tag color={routeSelfHealRaw?.route?.split_v4?.route_0_1?.on_tun ? "green" : "red"}>
                                  {routeSelfHealRaw?.route?.split_v4?.route_0_1?.on_tun ? "已指向 TUN" : "未指向 TUN"}
                                </Tag>
                              ) : (
                                <Tag>不存在</Tag>
                              )}
                              <Typography.Text code style={{display: "block", marginTop: 6}}>
                                {routeSelfHealRaw?.route?.split_v4?.route_0_1?.output || "-"}
                              </Typography.Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="分片路由 128.0.0.0/1">
                              {routeSelfHealRaw?.route?.split_v4?.route_128_1?.present ? (
                                <Tag color={routeSelfHealRaw?.route?.split_v4?.route_128_1?.on_tun ? "green" : "red"}>
                                  {routeSelfHealRaw?.route?.split_v4?.route_128_1?.on_tun ? "已指向 TUN" : "未指向 TUN"}
                                </Tag>
                              ) : (
                                <Tag>不存在</Tag>
                              )}
                              <Typography.Text code style={{display: "block", marginTop: 6}}>
                                {routeSelfHealRaw?.route?.split_v4?.route_128_1?.output || "-"}
                              </Typography.Text>
                            </Descriptions.Item>
                          </Descriptions>
                          {routeSelfHealRaw?.health?.ok === false ? (
                            <Alert
                              style={{marginBottom: 12}}
                              type="error"
                              showIcon
                              message="检测到路由风险"
                              description={(routeSelfHealRaw?.health?.issues || []).join("; ")}
                            />
                          ) : (
                            <Alert
                              style={{marginBottom: 12}}
                              type="success"
                              showIcon
                              message="当前路由状态正常"
                            />
                          )}
                          <Typography.Title level={5} style={{marginTop: 0}}>最近自愈动作</Typography.Title>
                          {isMobile ? (
                            <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                              {(routeSelfHealRaw?.self_heal?.recent || []).map((item, idx) => (
                                <Card key={`route-heal-mobile-${idx}`} size="small">
                                  <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                    <Typography.Text strong>{formatDateTimeCST(item.time)}</Typography.Text>
                                    <Tag color={String(item?.level || "").toLowerCase() === "warn" ? "orange" : "blue"}>
                                      {String(item?.level || "-").toUpperCase()}
                                    </Tag>
                                  </Space>
                                  <Typography.Text style={{display: "block", marginTop: 8}}>{item.action || "-"}</Typography.Text>
                                  <Typography.Text type="secondary" style={{display: "block", marginTop: 4}}>
                                    {item.detail || "-"}
                                  </Typography.Text>
                                </Card>
                              ))}
                              {(routeSelfHealRaw?.self_heal?.recent || []).length === 0 ? (
                                <Typography.Text type="secondary">暂无自愈动作记录</Typography.Text>
                              ) : null}
                            </Space>
                          ) : (
                            <Table
                              rowKey={(row, idx) => `${row?.time || "t"}-${row?.action || "a"}-${idx}`}
                              dataSource={routeSelfHealRaw?.self_heal?.recent || []}
                              columns={routeSelfHealEventColumns}
                              pagination={false}
                              scroll={{y: 360}}
                            />
                          )}
                        </>
                      ) : (
                        <Typography.Text type="secondary">暂无路由自愈数据，点击“刷新状态”获取。</Typography.Text>
                      )}
                    </>
                  )
                },
                {
                  key: "mitm",
                  label: "MITM",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Button type="primary" loading={mitmSaving} onClick={saveMITMConfig}>保存 MITM 配置</Button>
                        <Button icon={<DownloadOutlined />} loading={mitmDownloading} onClick={downloadMITMCA}>下载 CA 证书</Button>
                        <Button loading={mitmCheckingCA} onClick={() => loadMITMCAStatus()}>检测 CA 状态</Button>
                        <Button type="default" loading={mitmInstallingCA} onClick={autoInstallMITMCA}>自动安装 CA</Button>
                        <Button icon={<CopyOutlined />} loading={mitmCopyingCommand} onClick={copyMITMInstallCommand}>复制安装 CA 命令</Button>
                        <Button onClick={refreshAll} loading={loading}>从运行配置刷新</Button>
                      </Space>
                      {mitmCAStatus ? (
                        <Alert
                          style={{marginBottom: 12}}
                          type={mitmCAStatus.installed ? "success" : "warning"}
                          showIcon
                          message={mitmCAStatus.installed ? "MITM CA 已安装" : "MITM CA 未安装"}
                          description={
                            <>
                              <div>平台: {mitmCAStatus.os || "-"}</div>
                              <div>安装方式: {mitmCAStatus.mode || "-"}</div>
                              <div>位置: {mitmCAStatus.location || "-"}</div>
                              <div>说明: {mitmCAStatus.message || "-"}</div>
                            </>
                          }
                        />
                      ) : null}
                      <Form form={mitmForm} layout="vertical">
                        <Form.Item label="启用 MITM" name="mitm_enabled" valuePropName="checked">
                          <Switch />
                        </Form.Item>
                        <Form.Item label="MITM 监听地址" name="mitm_listen" rules={[{required: true}]}>
                          <Input style={{width: 260}} placeholder="127.0.0.1:1090" />
                        </Form.Item>
                        <Form.Item
                          label="MITM 主机列表（每行一条）"
                          name="mitm_hosts"
                          tooltip="支持精确域名和通配符：example.com / *.example.com"
                        >
                          <Input.TextArea rows={8} style={{fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}} placeholder={"video-dsp.pddpic.com\nt-dsp.pinduoduo.com\nimages.pinduoduo.com\n*.example.com"} />
                        </Form.Item>
                        <Form.Item
                          label="URL Reject 规则（每行一条正则）"
                          name="mitm_url_reject"
                          tooltip="命中后返回 403，等价于 Surge [URL Rewrite] 的 reject 效果"
                        >
                          <Input.TextArea rows={10} style={{fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}} placeholder={"^https:\\/\\/video-dsp\\.pddpic\\.com\\/market-dsp-video\\/\n^https:\\/\\/t-dsp\\.pinduoduo\\.com\\/dspcb\\/i\\/mrk_"} />
                        </Form.Item>
                        <Divider orientation="left">DoH/DoT 劫持</Divider>
                        <Form.Item
                          label="启用 DoH/DoT MITM 劫持"
                          name="mitm_doh_dot_enabled"
                          valuePropName="checked"
                          tooltip="仅在 MITM 开启时生效。DoH 仅匹配下方主机列表；DoT(853) 在 dot_hosts 为空时对所有 DoT 连接生效。"
                        >
                          <Switch />
                        </Form.Item>
                        <Form.Item
                          label="DoH 主机列表（每行一条）"
                          name="mitm_doh_hosts"
                          tooltip="用于匹配 443 上的 DoH 目标域名，支持 *.example.com"
                        >
                          <Input.TextArea rows={6} style={{fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}} placeholder={"dns.google\ncloudflare-dns.com\ndoh.pub"} />
                        </Form.Item>
                        <Form.Item
                          label="DoT 主机白名单（每行一条，可留空）"
                          name="mitm_dot_hosts"
                          tooltip="留空表示劫持全部 853 DoT；填写后仅劫持命中的主机"
                        >
                          <Input.TextArea rows={4} style={{fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}} placeholder={"dns.google\ncloudflare-dns.com"} />
                        </Form.Item>
                        <Alert
                          type="info"
                          showIcon
                          message="保存后立即生效。下载 CA 后需导入系统信任，DoH/DoT MITM 劫持模式仅在 MITM 开启时启用。"
                        />
                      </Form>
                    </>
                  )
                },
                {
                  key: "logs",
                  label: "日志管理",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Select
                          value={logLevel}
                          onChange={setLogLevel}
                          style={{width: 140}}
                          options={[
                            {value: "", label: "全部级别"},
                            {value: "debug", label: "DEBUG"},
                            {value: "info", label: "INFO"},
                            {value: "warn", label: "WARN"},
                            {value: "error", label: "ERROR"},
                          ]}
                        />
                        <Input
                          placeholder="关键词过滤"
                          value={logSearch}
                          onChange={(e) => setLogSearch(e.target.value)}
                          style={{width: 220}}
                        />
                        <InputNumber min={50} max={2000} value={logLimit} onChange={(v) => setLogLimit(v || 300)} />
                        <Checkbox checked={logCurrentNodeOnly} onChange={(e) => setLogCurrentNodeOnly(e.target.checked)}>
                          仅看当前节点错误
                        </Checkbox>
                        <Checkbox checked={logAutoRefresh} onChange={(e) => setLogAutoRefresh(e.target.checked)}>自动刷新</Checkbox>
                        <Button onClick={loadLogs} loading={logLoading}>刷新日志</Button>
                        <Popconfirm title="确认清空日志？" onConfirm={clearLogs}>
                          <Button danger loading={logLoading}>清空日志</Button>
                        </Popconfirm>
                      </Space>
                      {logCurrentNodeOnly ? (
                        <Typography.Text type="secondary" style={{display: "block", marginBottom: 8}}>
                          当前过滤节点: {current || "-"} {currentNode?.server ? `(${currentNode.server})` : ""}
                        </Typography.Text>
                      ) : null}
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(logs || []).map((item) => {
                            const level = String(item?.level || "").toLowerCase();
                            const levelColor = level === "error" || level === "fatal"
                              ? "red"
                              : (level === "warn" || level === "warning" ? "orange" : "blue");
                            return (
                              <Card key={`log-mobile-${item.id}`} size="small">
                                <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                  <Typography.Text strong>{formatDateTimeCST(item.time)}</Typography.Text>
                                  <Tag color={levelColor}>{String(item.level || "-").toUpperCase()}</Tag>
                                </Space>
                                <Typography.Paragraph style={{marginTop: 8, marginBottom: 0, whiteSpace: "pre-wrap"}}>
                                  {item.message || "-"}
                                </Typography.Paragraph>
                              </Card>
                            );
                          })}
                          {(logs || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无日志</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="id"
                          loading={logLoading}
                          dataSource={logs}
                          columns={logColumns}
                          pagination={false}
                          scroll={{y: 420}}
                        />
                      )}
                    </>
                  )
                },
                {
                  key: "subscriptions",
                  label: "订阅管理",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Button type="primary" onClick={openCreateSubscription}>新增订阅</Button>
                        <Button loading={subscriptionLoading} onClick={loadSubscriptions}>刷新订阅</Button>
                        <Button loading={subscriptionUpdatingAll} disabled={tunTaskBusy || subscriptionUpdating} onClick={() => updateSubscriptionNow("")}>手动更新全部</Button>
                      </Space>
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(subscriptions || []).map((item) => (
                            <Card key={item.id} size="small">
                              <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                <Typography.Text strong>{item.name || item.id}</Typography.Text>
                                {item.enabled ? <Tag color="blue">启用</Tag> : <Tag>停用</Tag>}
                              </Space>
                              <div style={{marginTop: 8}}>
                                <Typography.Text copyable={item.url ? {text: item.url} : false} style={{wordBreak: "break-all"}}>
                                  {item.url || "-"}
                                </Typography.Text>
                              </div>
                              <Space size={[4, 4]} wrap style={{marginTop: 8}}>
                                {Array.isArray(item.groups) && item.groups.length > 0 ? (
                                  item.groups.map((g) => <Tag key={`${item.id}-group-${g}`}>{g}</Tag>)
                                ) : (
                                  <Typography.Text type="secondary">未分组</Typography.Text>
                                )}
                              </Space>
                              <div style={{marginTop: 8}}>
                                <Typography.Text type="secondary">识别格式: {item?.status?.result?.source_format || "-"}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">解析摘要: {formatSubscriptionParseSummary(item?.status?.result?.parse_summary)}</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">间隔: {item.update_interval_sec || "-"}s</Typography.Text>
                                <br />
                                <Typography.Text type="secondary">上次成功: {formatDateTimeCST(item?.status?.last_success_at)}</Typography.Text>
                              </div>
                              {item?.status?.error ? (
                                <Alert style={{marginTop: 8}} type="error" showIcon message={item.status.error} />
                              ) : null}
                              <Space style={{marginTop: 10}} wrap>
                                <Button size="small" onClick={() => openEditSubscription(item)}>编辑</Button>
                                <Button size="small" loading={!!subscriptionUpdatingIDs[item.id]} disabled={tunTaskBusy || subscriptionUpdatingAll} onClick={() => updateSubscriptionNow(item.id)}>手动更新</Button>
                                <Popconfirm title={`删除订阅 ${item.name} ?`} onConfirm={() => deleteSubscription(item.id)}>
                                  <Button size="small" danger>删除</Button>
                                </Popconfirm>
                              </Space>
                            </Card>
                          ))}
                          {(subscriptions || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无订阅</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="id"
                          loading={subscriptionLoading}
                          dataSource={subscriptions}
                          columns={subscriptionColumns}
                          tableLayout="fixed"
                          scroll={{x: 1560}}
                          pagination={false}
                        />
                      )}
                    </>
                  )
                },
                {
                  key: "tasks",
                  label: "任务中心",
                  children: (
                    <>
                      <Space style={{marginBottom: 12}} wrap>
                        <Button loading={taskCenterLoading} onClick={loadTaskCenter}>刷新任务</Button>
                        <Checkbox checked={taskCenterAutoRefresh} onChange={(e) => setTaskCenterAutoRefresh(e.target.checked)}>自动刷新</Checkbox>
                      </Space>
                      {taskCenterQueue ? (
                        <Alert
                          style={{marginBottom: 12}}
                          showIcon
                          type={taskCenterQueue?.worker_stale ? "warning" : "info"}
                          message={`TUN 队列总览: ${buildTaskQueueOverviewText(taskCenterQueue)}`}
                          description={`Worker: ${taskCenterQueue?.worker_running ? "运行中" : "空闲"}${taskCenterQueue?.worker_stale ? "（心跳异常）" : ""} · 最近心跳 ${formatDateTimeCST(taskCenterQueue?.worker_last_beat_at)} · 最近唤醒 ${formatDateTimeCST(taskCenterQueue?.worker_last_kick_at)} · 平均耗时 ${formatSecondsCN(taskCenterQueue?.avg_duration_seconds)}`}
                        />
                      ) : null}
                      {isMobile ? (
                        <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                          {(taskCenterItems || []).map((item) => {
                            const status = String(item?.status || "").toLowerCase();
                            const color = status === "success"
                              ? "green"
                              : status === "failed"
                                ? "red"
                                : status === "running"
                                  ? "processing"
                                  : "default";
                            const label = status === "success"
                              ? "成功"
                              : status === "failed"
                                ? "失败"
                                : status === "running"
                                  ? "执行中"
                                  : "排队中";
                            const queueText = formatTaskQueueSummary(item);
                            const elapsedText = formatTaskElapsedSummary(item);
                            return (
                              <Card key={item.id} size="small">
                                <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                                  <Typography.Text strong>{String(item.kind || "-")}</Typography.Text>
                                  <Tag color={color}>{label}</Tag>
                                </Space>
                                <div style={{marginTop: 8}}>
                                  <Typography.Text type="secondary">创建: {formatDateTimeCST(item.created_at)}</Typography.Text>
                                  <br />
                                  <Typography.Text type="secondary">完成: {formatDateTimeCST(item.finished_at)}</Typography.Text>
                                  <br />
                                  <Typography.Text>{item.message || "-"}</Typography.Text>
                                  {queueText !== "-" ? (
                                    <>
                                      <br />
                                      <Typography.Text type="secondary">队列: {queueText}</Typography.Text>
                                    </>
                                  ) : null}
                                  {elapsedText ? (
                                    <>
                                      <br />
                                      <Typography.Text type="secondary">{elapsedText}</Typography.Text>
                                    </>
                                  ) : null}
                                  {item.error ? (
                                    <>
                                      <br />
                                      <Typography.Text type="danger">{item.error}</Typography.Text>
                                    </>
                                  ) : null}
                                </div>
                              </Card>
                            );
                          })}
                          {(taskCenterItems || []).length === 0 ? (
                            <Typography.Text type="secondary">暂无任务记录</Typography.Text>
                          ) : null}
                        </Space>
                      ) : (
                        <Table
                          rowKey="id"
                          loading={taskCenterLoading}
                          dataSource={taskCenterItems}
                          columns={taskCenterColumns}
                          pagination={false}
                          scroll={{x: 1220, y: 420}}
                        />
                      )}
                    </>
                  )
                }
              ]}
            />
          </Card>
        </Space>
      </div>

      <Modal
        title="基础配置"
        open={configVisible}
        onCancel={() => setConfigVisible(false)}
        width={980}
        footer={[
          <Button key="cancel" onClick={() => setConfigVisible(false)}>关闭</Button>,
          <Button key="save" type="primary" loading={savingConfig} onClick={saveConfig}>保存配置</Button>,
        ]}
      >
        <Space style={{marginBottom: 12}} wrap>
          <Button onClick={refreshAll} loading={loading}>刷新</Button>
          <Button onClick={runDiagnose} loading={diagnosing} disabled={tunTaskBusy}>一键诊断</Button>
          <Button onClick={runRouteCheck} loading={routeCheckLoading} disabled={tunTaskBusy}>路由自检</Button>
          <Button onClick={runTunCheck} loading={tunCheckLoading} disabled={tunTaskBusy}>测试连接(TUN)</Button>
          <Button onClick={loadBackups} loading={backupLoading}>配置备份</Button>
        </Space>
        <Form layout="vertical" form={configForm}>
          <Space style={{display: "flex"}} align="start" wrap>
            <Form.Item label="本地代理监听" name="listen" rules={[{required: true}]}>
              <Input style={{width: 220}} />
            </Form.Item>
            <Form.Item label="API 监听地址" name="control" rules={[{required: true}]}>
              <Input style={{width: 220}} />
            </Form.Item>
            <Form.Item label="Web 用户名" name="web_username">
              <Input style={{width: 180}} />
            </Form.Item>
            <Form.Item label="Web 密码" name="web_password">
              <Input.Password style={{width: 180}} />
            </Form.Item>
            <Form.Item label="最小空闲会话" name="min_idle_session" rules={[{required: true}]}>
              <InputNumber style={{width: 140}} min={1} />
            </Form.Item>
            <Form.Item label="默认节点" name="default_node" rules={[{required: true, message: "请选择默认节点"}]}>
              <Select
                style={{width: 220}}
                placeholder={nodes.length ? "请选择默认节点" : "暂无可用节点"}
                options={(nodes || []).map((n) => ({value: n.name, label: n.name}))}
                showSearch
                optionFilterProp="label"
                disabled={!nodes.length}
              />
            </Form.Item>
          </Space>

          <Divider orientation="left">TUN</Divider>
          <Space style={{display: "flex"}} align="start" wrap>
            <Form.Item label="启用 TUN" name="tun_enabled" valuePropName="checked">
              <Switch loading={tunApplying} onChange={(checked) => applyTunToggle(checked)} />
            </Form.Item>
            <Form.Item label="设备名" name="tun_name"><Input style={{width: 160}} /></Form.Item>
            <Form.Item label="MTU" name="tun_mtu"><InputNumber style={{width: 120}} min={1200} max={9000} /></Form.Item>
            <Form.Item label="地址网段" name="tun_address"><Input style={{width: 220}} /></Form.Item>
            <Form.Item label="自动路由" name="tun_auto_route" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item label="启用时关闭其他代理(macOS)" name="tun_disable_other_proxies" valuePropName="checked"><Switch /></Form.Item>
          </Space>
          <Typography.Text type="secondary">TUN 开关会立即生效：开启后接管全局流量，关闭后恢复普通网络。</Typography.Text>
          <div style={{marginTop: 8}}>
            <Button size="small" onClick={runTunCheck} loading={tunCheckLoading} disabled={tunTaskBusy}>测试连接(TUN)</Button>
          </div>
          {tunTaskProgress ? (
            <Alert
              style={{marginTop: 10}}
              showIcon
              type={
                String(tunTaskProgress.status || "").toLowerCase() === "failed"
                  ? "error"
                  : String(tunTaskProgress.status || "").toLowerCase() === "success"
                    ? "success"
                    : "info"
              }
              message={`TUN 任务状态: ${
                String(tunTaskProgress.status || "").toLowerCase() === "running"
                  ? "执行中"
                  : String(tunTaskProgress.status || "").toLowerCase() === "success"
                    ? "成功"
                    : String(tunTaskProgress.status || "").toLowerCase() === "failed"
                      ? "失败"
                      : "排队中"
              }`}
              description={
                <div>
                  <div>{buildTaskProgressDescription(tunTaskProgress, tunProgressTick)}</div>
                  {Array.isArray(tunTaskProgress?._logs) && tunTaskProgress._logs.length > 0 ? (
                    <div style={{marginTop: 8}}>
                      <Typography.Text strong>步骤日志</Typography.Text>
                      <div style={{marginTop: 4, maxHeight: 180, overflowY: "auto", padding: "6px 8px", background: "rgba(0,0,0,0.03)", borderRadius: 6}}>
                        <pre style={{margin: 0, whiteSpace: "pre-wrap"}}>{tunTaskProgress._logs.map((item) => `${formatClockTime(item?.at)}  ${String(item?.text || "").trim()}`).join("\n")}</pre>
                      </div>
                    </div>
                  ) : null}
                </div>
              }
            />
          ) : null}
          {tunCheckProgress ? (
            <Alert
              style={{marginTop: 10}}
              showIcon
              type={
                String(tunCheckProgress.status || "").toLowerCase() === "failed"
                  ? "error"
                  : String(tunCheckProgress.status || "").toLowerCase() === "success"
                    ? "success"
                    : String(tunCheckProgress.status || "").toLowerCase() === "issues"
                      ? "warning"
                      : "info"
              }
              message={`TUN 测试状态: ${
                String(tunCheckProgress.status || "").toLowerCase() === "running"
                  ? "执行中"
                  : String(tunCheckProgress.status || "").toLowerCase() === "success"
                    ? "通过"
                    : String(tunCheckProgress.status || "").toLowerCase() === "issues"
                      ? "发现问题"
                      : String(tunCheckProgress.status || "").toLowerCase() === "failed"
                        ? "失败"
                        : "排队中"
              }`}
              description={
                <div>
                  <div>{buildTaskProgressDescription(tunCheckProgress, tunProgressTick)}</div>
                  {Array.isArray(tunCheckProgress?._logs) && tunCheckProgress._logs.length > 0 ? (
                    <div style={{marginTop: 8}}>
                      <Typography.Text strong>测试日志</Typography.Text>
                      <div style={{marginTop: 4, maxHeight: 180, overflowY: "auto", padding: "6px 8px", background: "rgba(0,0,0,0.03)", borderRadius: 6}}>
                        <pre style={{margin: 0, whiteSpace: "pre-wrap"}}>{tunCheckProgress._logs.map((item) => `${formatClockTime(item?.at)}  ${String(item?.text || "").trim()}`).join("\n")}</pre>
                      </div>
                    </div>
                  ) : null}
                </div>
              }
            />
          ) : null}

          <Divider orientation="left">Failover</Divider>
          <Space style={{display: "flex"}} align="start" wrap>
            <Form.Item label="启用自动故障切换" name="failover_enabled" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item label="探测间隔(秒)" name="failover_check_interval_sec">
              <InputNumber style={{width: 160}} min={3} max={300} />
            </Form.Item>
            <Form.Item label="连续失败阈值" name="failover_failure_threshold">
              <InputNumber style={{width: 160}} min={1} max={10} />
            </Form.Item>
            <Form.Item label="探测目标" name="failover_probe_target">
              <Input style={{width: 220}} placeholder="1.1.1.1:443" />
            </Form.Item>
            <Form.Item label="探测超时(ms)" name="failover_probe_timeout_ms">
              <InputNumber style={{width: 180}} min={300} max={30000} />
            </Form.Item>
            <Form.Item label="故障时切到最低延迟节点" name="failover_best_latency_enabled" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
        </Form>
      </Modal>

      <Modal
        title="新增节点"
        open={addNodeVisible}
        onCancel={() => setAddNodeVisible(false)}
        footer={null}
        width={980}
      >
        <Tabs
          items={[
            {
              key: "import",
              label: "URI 一键导入",
              children: (
                <Form form={importForm} layout="inline">
                  <Form.Item name="uri" label="URI" rules={[{required: true}]}>
                    <Input style={{width: 520}} placeholder="anytls:// / ss:// / vmess:// / vless:// / trojan:// / hy2:// / tuic:// / wireguard:// / ssh:// / socks5:// / singbox:// / mihomo://" />
                  </Form.Item>
                  <Form.Item name="name" label="节点名">
                    <Input style={{width: 180}} placeholder="可留空自动生成" />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" loading={savingNode} onClick={importNode}>导入</Button>
                  </Form.Item>
                </Form>
              )
            },
            {
              key: "manual",
              label: "按属性新增",
              children: (
                <Form form={manualForm} layout="inline">
                  <Form.Item name="name" label="节点名" rules={[{required: true}]}>
                    <Input style={{width: 150}} />
                  </Form.Item>
                  <Form.Item name="server" label="服务器" rules={[{required: true}]}>
                    <Input style={{width: 200}} placeholder="host:port" />
                  </Form.Item>
                  <Form.Item name="password" label="密码" rules={[{required: true}]}>
                    <Input style={{width: 180}} />
                  </Form.Item>
                  <Form.Item name="sni" label="SNI"><Input style={{width: 150}} /></Form.Item>
                  <Form.Item name="groups" label="分组">
                    <Select
                      mode="tags"
                      style={{width: 220}}
                      options={groupOptions}
                      placeholder="可多选/可新建"
                    />
                  </Form.Item>
                  <Form.Item name="egress_ip" label="egress-ip"><Input style={{width: 150}} /></Form.Item>
                  <Form.Item name="egress_rule" label="egress-rule"><Input style={{width: 220}} /></Form.Item>
                  <Form.Item>
                    <Button type="primary" loading={savingNode} onClick={createNode}>新增</Button>
                  </Form.Item>
                </Form>
              )
            }
          ]}
        />
      </Modal>

      <Modal
        title={editingRoutingRuleIndex >= 0 ? "编辑规则" : "新增规则"}
        open={routingRuleModalVisible}
        onCancel={() => setRoutingRuleModalVisible(false)}
        onOk={saveRoutingRule}
      >
        <Form
          layout="vertical"
          form={routingRuleForm}
          onValuesChange={(changedValues) => {
            if (!Object.prototype.hasOwnProperty.call(changedValues || {}, "rule_type")) {
              return;
            }
            const nextRuleType = String(changedValues?.rule_type || "").toUpperCase();
            const currentActionKind = String(routingRuleForm.getFieldValue("action_kind") || "").toLowerCase();
            if (nextRuleType === "RULE-SET") {
              if (currentActionKind !== "inherit") {
                routingRuleForm.setFieldsValue({
                  action_kind: "inherit",
                  action_group: "",
                  action_node: "",
                });
              }
              return;
            }
            if (currentActionKind === "inherit") {
              routingRuleForm.setFieldsValue({
                action_kind: "group",
                action_group: String(routingActionGroupOptions?.[0]?.value || ""),
                action_node: "",
              });
            }
          }}
        >
          <Form.Item label="规则类型" name="rule_type" rules={[{required: true, message: "请选择规则类型"}]}>
            <Select options={ROUTING_RULE_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item shouldUpdate={(prev, next) => prev.rule_type !== next.rule_type || prev.action_kind !== next.action_kind} noStyle>
            {({getFieldValue}) => {
              const ruleType = String(getFieldValue("rule_type") || "").toUpperCase();
              const actionKind = String(getFieldValue("action_kind") || "").toLowerCase();
              const showAdvanced = ruleType === "ADVANCED";
              const isLogical = ROUTING_RULE_LOGICAL_TYPES.has(ruleType);
              return (
                <>
                  {showAdvanced ? (
                    <Form.Item
                      label="高级规则"
                      name="raw_rule"
                      rules={[{required: true, message: "请输入高级规则"}]}
                      tooltip="用于 AND/OR/NOT 等复杂规则，例如: AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443)),GROUP:hk"
                    >
                      <Input placeholder="请输入完整规则字符串" />
                    </Form.Item>
                  ) : (
                    <>
                      {isLogical ? (
                        <Form.List name="logical_children">
                          {(fields, {add, remove}) => (
                            <>
                              {fields.map((field, idx) => (
                                <Card
                                  key={field.key}
                                  size="small"
                                  style={{marginBottom: 10}}
                                  title={`子条件 ${idx + 1}`}
                                  extra={fields.length > 1 ? <Button size="small" danger onClick={() => remove(field.name)}>删除</Button> : null}
                                >
                                  <Form.Item
                                    label="子条件类型"
                                    name={[field.name, "type"]}
                                    rules={[{required: true, message: "请选择子条件类型"}]}
                                  >
                                    <Select options={ROUTING_LOGICAL_CHILD_TYPE_OPTIONS} />
                                  </Form.Item>
                                  <Form.Item shouldUpdate={(prev, next) => {
                                    const pType = prev?.logical_children?.[field.name]?.type;
                                    const nType = next?.logical_children?.[field.name]?.type;
                                    return pType !== nType;
                                  }} noStyle>
                                    {({getFieldValue: getInnerValue}) => {
                                      const childType = String(getInnerValue(["logical_children", field.name, "type"]) || "").toUpperCase();
                                      if (childType === "ADVANCED") {
                                        return (
                                          <Form.Item
                                            label="子条件高级规则"
                                            name={[field.name, "raw_rule"]}
                                            rules={[{required: true, message: "请输入子条件高级规则"}]}
                                          >
                                            <Input placeholder="例如: OR,((DOMAIN-SUFFIX,google.com),(DST-PORT,443))" />
                                          </Form.Item>
                                        );
                                      }
                                      if (childType === "RULE-SET") {
                                        return (
                                          <Form.Item
                                            label="规则集"
                                            name={[field.name, "provider_name"]}
                                            rules={[{required: true, message: "请选择规则集"}]}
                                          >
                                            <Select
                                              showSearch
                                              options={(routingProviderConfigs || []).map((item) => ({value: item.name, label: item.name}))}
                                              placeholder="请选择规则集"
                                            />
                                          </Form.Item>
                                        );
                                      }
                                      if (childType === "MATCH" || childType === "") {
                                        return null;
                                      }
                                      return (
                                        <Form.Item
                                          label={getRulePayloadLabel(childType)}
                                          name={[field.name, "match_value"]}
                                          rules={[{required: true, message: "请输入匹配值"}]}
                                        >
                                          <Input placeholder={getRulePayloadPlaceholder(childType)} />
                                        </Form.Item>
                                      );
                                    }}
                                  </Form.Item>
                                </Card>
                              ))}
                              <Button
                                type="dashed"
                                onClick={() => add(defaultLogicalChild())}
                                disabled={ruleType === "NOT" && fields.length >= 1}
                              >
                                添加子条件
                              </Button>
                            </>
                          )}
                        </Form.List>
                      ) : null}
                      {!isLogical && ruleType === "RULE-SET" ? (
                        <Form.Item
                          label="规则集"
                          name="provider_name"
                          rules={[{required: true, message: "请选择规则集"}]}
                        >
                          <Select
                            showSearch
                            options={(routingProviderConfigs || []).map((item) => ({value: item.name, label: item.name}))}
                            placeholder="请选择已添加的规则集"
                          />
                        </Form.Item>
                      ) : null}
                      {!isLogical && ruleType !== "RULE-SET" && ruleType !== "MATCH" ? (
                        <Form.Item
                          label={getRulePayloadLabel(ruleType)}
                          name="match_value"
                          rules={[{required: true, message: "请输入匹配值"}]}
                        >
                          <Input placeholder={getRulePayloadPlaceholder(ruleType)} />
                        </Form.Item>
                      ) : null}
                      <Form.Item label="动作" name="action_kind" rules={[{required: true, message: "请选择动作"}]}>
                        <Select options={[
                          ...(ruleType === "RULE-SET" ? [{value: "inherit", label: "继承规则集动作（推荐）"}] : []),
                          {value: "group", label: "转发到分组"},
                          {value: "direct", label: "DIRECT 直连"},
                          {value: "reject", label: "REJECT 拒绝"},
                          {value: "proxy", label: "PROXY 默认代理"},
                          {value: "node", label: "转发到节点（兼容）"},
                        ]} />
                      </Form.Item>
                      {actionKind === "group" ? (
                        <Form.Item
                          label="目标分组"
                          name="action_group"
                          rules={[{required: true, message: "请选择目标分组"}]}
                        >
                          <Select
                            showSearch
                            options={routingActionGroupOptions}
                            placeholder="请选择分组"
                          />
                        </Form.Item>
                      ) : null}
                      {actionKind === "node" ? (
                        <Form.Item
                          label="目标节点"
                          name="action_node"
                          rules={[{required: true, message: "请选择目标节点"}]}
                        >
                          <Select
                            showSearch
                            options={(nodes || []).map((item) => ({value: item.name, label: item.name}))}
                            placeholder="请选择节点"
                          />
                        </Form.Item>
                      ) : null}
                    </>
                  )}
                </>
              );
            }}
          </Form.Item>
          <Alert
            type="info"
            showIcon
            message="按选项生成规则：支持 AND/OR/NOT 子条件可视化拼装。RULE-SET 动作可选“继承规则集动作（推荐）”；仅超复杂嵌套场景需要“高级(手写)”。"
          />
        </Form>
      </Modal>

      <Modal
        title={editingGeoIPProvider ? "编辑 GEOIP(mmdb)" : (editingRoutingProviderName ? `编辑规则集: ${editingRoutingProviderName}` : "新增规则集")}
        open={routingProviderModalVisible}
        onCancel={() => {
          setRoutingProviderModalVisible(false);
          setRoutingProbeResult(null);
        }}
        onOk={saveRoutingProvider}
      >
        <Form layout="vertical" form={routingProviderForm}>
          <Form.Item label={editingGeoIPProvider ? "名称" : "规则集名称"} name="name" rules={[{required: true, message: "请输入规则集名称"}]}>
            <Input placeholder={editingGeoIPProvider ? "geoip" : "ads / google / telegram"} disabled={!!editingRoutingProviderName} />
          </Form.Item>
          <Form.Item label={editingGeoIPProvider ? "GEOIP 来源类型" : "类型"} name="type" rules={[{required: true}]}>
            <Select options={editingGeoIPProvider ? [
              {value: "http", label: "http 下载 mmdb"},
              {value: "file", label: "file 本地 mmdb"},
            ] : [
              {value: "http", label: "http 远程规则"},
              {value: "file", label: "file 本地规则"},
            ]} />
          </Form.Item>
          {!editingGeoIPProvider ? (
            <Form.Item label="匹配行为" name="behavior" tooltip="留空自动识别（mrs 自动取内置行为，其他格式默认 classical）">
              <Select allowClear options={[
                {value: "classical", label: "classical"},
                {value: "domain", label: "domain"},
                {value: "ipcidr", label: "ipcidr"},
              ]} />
            </Form.Item>
          ) : null}
          <Form.Item shouldUpdate={(prev, next) => prev.type !== next.type} noStyle>
            {({getFieldValue}) => getFieldValue("type") === "http" ? (
              <>
                <Form.Item
                  label={editingGeoIPProvider ? "GEOIP 下载地址" : "规则 URL"}
                  name="url"
                  rules={[{required: true, message: editingGeoIPProvider ? "请输入 GEOIP 下载地址" : "请输入 URL"}]}
                >
                  <Input placeholder={editingGeoIPProvider ? "https://static-sg.529851.xyz/GeoLite2-Country.mmdb" : "https://example.com/rules.yaml / .mrs / .sgmodule"} />
                </Form.Item>
                <Form.Item label={editingGeoIPProvider ? "GEOIP 更新间隔(秒)" : "更新间隔(秒)"} name="interval_sec">
                  <InputNumber min={60} max={86400 * 30} style={{width: "100%"}} />
                </Form.Item>
              </>
            ) : (
              <Form.Item
                label={editingGeoIPProvider ? "GEOIP 本地路径" : "本地文件路径"}
                name="path"
                rules={[{required: true, message: editingGeoIPProvider ? "请输入 GEOIP 本地路径" : "请输入文件路径"}]}
              >
                <Input placeholder={editingGeoIPProvider ? "/etc/anytls/GeoLite2-Country.mmdb" : "/etc/anytls/rules/custom.list"} />
              </Form.Item>
            )}
          </Form.Item>
          {!editingGeoIPProvider ? (
            <Space style={{marginBottom: 12}} wrap>
              <Button loading={routingProbeLoading} disabled={tunTaskBusy} onClick={probeRoutingProviderSource}>探测预览</Button>
            </Space>
          ) : null}
          {!editingGeoIPProvider && routingProbeResult ? (
            <Card size="small" style={{marginBottom: 12}} title="探测结果">
              <Space wrap style={{marginBottom: 8}}>
                <Tag color="blue">格式: {routingProbeResult.detected_format || "-"}</Tag>
                <Tag color="processing">建议行为: {routingProbeResult.suggested_behavior || "-"}</Tag>
                <Tag>规则数: {routingProbeResult.entry_count || 0}</Tag>
                <Tag>MITM Hosts: {routingProbeResult.mitm_host_count || 0}</Tag>
                <Tag>URL Reject: {routingProbeResult.url_reject_count || 0}</Tag>
              </Space>
              {Array.isArray(routingProbeResult.sample_rules) && routingProbeResult.sample_rules.length > 0 ? (
                <>
                  <Typography.Text strong>规则示例:</Typography.Text>
                  <pre style={{marginTop: 6, whiteSpace: "pre-wrap"}}>{routingProbeResult.sample_rules.join("\n")}</pre>
                </>
              ) : null}
              {Array.isArray(routingProbeResult.mitm_hosts) && routingProbeResult.mitm_hosts.length > 0 ? (
                <>
                  <Typography.Text strong>MITM Hosts 示例:</Typography.Text>
                  <pre style={{marginTop: 6, whiteSpace: "pre-wrap"}}>{routingProbeResult.mitm_hosts.join(", ")}</pre>
                </>
              ) : null}
            </Card>
          ) : null}
          <Alert
            type="info"
            showIcon
            message={editingGeoIPProvider ? "仅编辑 GEOIP(mmdb) 来源与更新间隔。保存后请点击“保存规则配置”使修改生效。" : "格式固定为 auto，保存后将按内容自动识别为 mrs/sgmodule/yaml/text。"}
          />
        </Form>
      </Modal>

      <Modal
        title={editingSubscriptionID ? "编辑订阅" : "新增订阅"}
        open={subscriptionModalVisible}
        onCancel={() => setSubscriptionModalVisible(false)}
        onOk={saveSubscription}
        confirmLoading={subscriptionSaving}
      >
        <Form layout="vertical" form={subscriptionForm}>
          {!editingSubscriptionID ? (
            <Form.Item
              label="订阅 ID（可留空自动生成）"
              name="id"
              rules={[{pattern: /^[a-zA-Z0-9._-]*$/, message: "仅支持字母数字._-"}]}
            >
              <Input placeholder="sub-my-group" />
            </Form.Item>
          ) : null}
          <Form.Item label="订阅名称" name="name">
            <Input placeholder="香港节点订阅" />
          </Form.Item>
          <Form.Item label="订阅 URL" name="url" rules={[{required: true, message: "请输入订阅链接"}]}>
            <Input placeholder="https://example.com/anytls-sub.txt" />
          </Form.Item>
          <Form.Item label="节点前缀" name="node_prefix">
            <Input placeholder="hk-sub" />
          </Form.Item>
          <Form.Item label="分组" name="groups">
            <Select
              mode="tags"
              options={groupOptions}
              placeholder="导入该订阅节点时自动附加这些分组"
            />
          </Form.Item>
          <Space style={{display: "flex"}} align="start">
            <Form.Item label="启用订阅" name="enabled" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item label="更新间隔(秒)" name="update_interval_sec">
              <InputNumber min={60} max={86400 * 30} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>

      <Modal title={`编辑节点: ${editNodeName}`} open={editVisible} onCancel={() => setEditVisible(false)} onOk={saveNodeEdit}>
        <Form layout="vertical" form={editForm}>
          <Form.Item label="服务器" name="server"><Input /></Form.Item>
          <Form.Item label="密码" name="password"><Input /></Form.Item>
          <Form.Item label="SNI" name="sni"><Input /></Form.Item>
          <Form.Item label="分组" name="groups">
            <Select
              mode="tags"
              options={groupOptions}
              placeholder="可多选/可新建"
            />
          </Form.Item>
          <Form.Item label="egress-ip" name="egress_ip"><Input /></Form.Item>
          <Form.Item label="egress-rule" name="egress_rule"><Input /></Form.Item>
        </Form>
      </Modal>

      <Modal
        title="分组管理"
        open={groupManageVisible}
        onCancel={() => setGroupManageVisible(false)}
        footer={[
          <Button key="close" onClick={() => setGroupManageVisible(false)}>关闭</Button>,
        ]}
        width={900}
      >
        <Tabs
          items={[
            {
              key: "overview",
              label: "分组概览",
              children: isMobile ? (
                <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
                  {(groupStatsRows || []).map((row) => (
                    <Card key={row.group} size="small">
                      <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                        <Typography.Text strong>{row.group}</Typography.Text>
                        <Tag color="blue">节点数: {row.count}</Tag>
                      </Space>
                      <Space style={{marginTop: 10}} wrap>
                        <Button
                          size="small"
                          onClick={() => {
                            groupRenameForm.setFieldsValue({source_group: row.group});
                            setGroupManageVisible(true);
                          }}
                        >
                          设为来源
                        </Button>
                        <Button
                          size="small"
                          onClick={() => {
                            groupRemoveForm.setFieldsValue({group: row.group});
                            setGroupManageVisible(true);
                          }}
                        >
                          设为移除
                        </Button>
                      </Space>
                    </Card>
                  ))}
                  {(groupStatsRows || []).length === 0 ? (
                    <Typography.Text type="secondary">暂无分组，请先在节点里新增 groups</Typography.Text>
                  ) : null}
                </Space>
              ) : (
                <Table
                  rowKey="group"
                  dataSource={groupStatsRows}
                  columns={groupStatsColumns}
                  pagination={false}
                  locale={{emptyText: "暂无分组，请先在节点里新增 groups"}}
                />
              )
            },
            {
              key: "rename-merge",
              label: "重命名 / 合并",
              children: (
                <Form layout="vertical" form={groupRenameForm}>
                  <Form.Item label="来源分组" name="source_group" rules={[{required: true, message: "请选择来源分组"}]}>
                    <Select showSearch options={groupOptions} placeholder="选择来源分组" />
                  </Form.Item>
                  <Form.Item label="目标分组" name="target_group" rules={[{required: true, message: "请输入目标分组"}]}>
                    <Input placeholder="输入新分组名，或填写已有分组名执行合并" />
                  </Form.Item>
                  <Button type="primary" loading={groupManaging} onClick={submitGroupRenameMerge}>执行重命名/合并</Button>
                </Form>
              )
            },
            {
              key: "remove",
              label: "批量移除",
              children: (
                <Form layout="vertical" form={groupRemoveForm}>
                  <Form.Item label="要移除的分组" name="group" rules={[{required: true, message: "请选择分组"}]}>
                    <Select showSearch options={groupOptions} placeholder="选择要从所有节点移除的分组" />
                  </Form.Item>
                  <Popconfirm title="确认从所有命中节点移除该分组？" onConfirm={submitGroupRemove}>
                    <Button danger loading={groupManaging}>执行移除</Button>
                  </Popconfirm>
                </Form>
              )
            }
          ]}
        />
      </Modal>

      <Modal title="一键诊断结果" open={diagnoseVisible} onCancel={() => setDiagnoseVisible(false)} footer={null} width={900}>
        <Space style={{marginBottom: 12}} wrap>
          <Button onClick={exportDiagnoseJSON}>导出 JSON</Button>
          <Button onClick={exportDiagnoseText}>导出文本</Button>
        </Space>
        {diagnoseSummary ? (
          <Alert
            style={{marginBottom: 12}}
            type={diagnoseSummary.ok ? "success" : "warning"}
            showIcon
            message={diagnoseSummary.ok ? "诊断通过" : `发现 ${diagnoseSummary.failed} 项异常`}
          />
        ) : null}
        {isMobile ? (
          <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
            {(diagnoseRows || []).map((row) => (
              <Card key={row.key} size="small">
                <Space style={{width: "100%", justifyContent: "space-between"}} wrap>
                  <Typography.Text strong>{row.name}</Typography.Text>
                  {row.ok ? <Tag color="blue">OK</Tag> : <Tag color="red">FAIL</Tag>}
                </Space>
                <div style={{marginTop: 8}}>
                  <Typography.Text type="secondary">延迟: {row.latency > 0 ? `${row.latency} ms` : "-"}</Typography.Text>
                </div>
                <div style={{marginTop: 6}}><Typography.Text>详情: {row.detail || "-"}</Typography.Text></div>
                {row.error ? <Alert style={{marginTop: 8}} type="error" showIcon message={row.error} /> : null}
              </Card>
            ))}
            {(diagnoseRows || []).length === 0 ? (
              <Typography.Text type="secondary">暂无诊断数据</Typography.Text>
            ) : null}
          </Space>
        ) : (
          <Table
            rowKey="key"
            dataSource={diagnoseRows}
            pagination={false}
            columns={[
              {title: "检查项", dataIndex: "name"},
              {title: "状态", dataIndex: "ok", render: (v) => v ? <Tag color="blue">OK</Tag> : <Tag color="red">FAIL</Tag>},
              {title: "延迟", dataIndex: "latency", render: (v) => v > 0 ? `${v} ms` : "-"},
              {title: "详情", dataIndex: "detail", render: (v) => v || "-"},
              {title: "错误", dataIndex: "error", render: (v) => v || "-"}
            ]}
          />
        )}
      </Modal>

      <Modal title="路由自检结果" open={routeCheckVisible} onCancel={() => setRouteCheckVisible(false)} footer={null} width={900}>
        {routeCheckRaw ? (
          <Space direction="vertical" style={{display: "flex"}}>
            <Space wrap>
              <Tag color={routeCheckRaw?.check?.ok ? "blue" : (routeCheckRaw?.check?.risk_loop ? "orange" : "red")}>
                {routeCheckRaw?.check?.ok ? "通过" : (routeCheckRaw?.check?.risk_loop ? "存在回环风险" : "异常")}
              </Tag>
              <Typography.Text type="secondary">系统: {routeCheckRaw.os || "-"} / {routeCheckRaw.arch || "-"}</Typography.Text>
              <Typography.Text type="secondary">节点: {routeCheckRaw.current || "-"}</Typography.Text>
            </Space>

            <Card size="small">
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label="服务端地址">{routeCheckRaw.server || "-"}</Descriptions.Item>
                <Descriptions.Item label="路由查询主机">{routeCheckRaw.server_host || "-"}</Descriptions.Item>
                <Descriptions.Item label="执行命令">{routeCheckRaw?.check?.command || "-"}</Descriptions.Item>
                <Descriptions.Item label="出口网卡">{routeCheckRaw?.check?.interface || "-"}</Descriptions.Item>
                <Descriptions.Item label="网关">{routeCheckRaw?.check?.gateway || "-"}</Descriptions.Item>
                <Descriptions.Item label="本地源地址">{routeCheckRaw?.check?.source || "-"}</Descriptions.Item>
                <Descriptions.Item label="TUN">{routeCheckRaw?.tun?.running ? `运行中 (${routeCheckRaw?.tun?.name || "-"})` : "未运行"}</Descriptions.Item>
              </Descriptions>
            </Card>

            {routeCheckRaw?.check?.error ? (
              <Alert type="error" showIcon message={routeCheckRaw.check.error} />
            ) : null}
            {Array.isArray(routeCheckRaw?.check?.advice) && routeCheckRaw.check.advice.length > 0 ? (
              <Alert
                type={routeCheckRaw?.check?.ok ? "info" : "warning"}
                showIcon
                message="建议"
                description={(
                  <ul style={{marginBottom: 0, paddingLeft: 18}}>
                    {routeCheckRaw.check.advice.map((item, idx) => (
                      <li key={`route-advice-${idx}`}>{item}</li>
                    ))}
                  </ul>
                )}
              />
            ) : null}

            <Card size="small" title="原始路由输出">
              <Typography.Paragraph copyable style={{whiteSpace: "pre-wrap", marginBottom: 0}}>
                {routeCheckRaw?.check?.raw || "-"}
              </Typography.Paragraph>
            </Card>
          </Space>
        ) : (
          <Typography.Text type="secondary">暂无自检数据</Typography.Text>
        )}
      </Modal>

      <Modal title="TUN 连通性测试结果" open={tunCheckVisible} onCancel={() => setTunCheckVisible(false)} footer={null} width={980}>
        {tunCheckRaw ? (
          <Space direction="vertical" style={{display: "flex"}}>
            <Alert
              showIcon
              type={tunCheckRaw?.summary?.ok ? "success" : "warning"}
              message={tunCheckRaw?.summary?.ok ? "TUN 连通性测试通过" : `发现 ${toPositiveInt(tunCheckRaw?.summary?.issue_count)} 个问题`}
              description={`步骤失败 ${toPositiveInt(tunCheckRaw?.summary?.failed_steps)} / ${toPositiveInt(tunCheckRaw?.summary?.total_steps)} · 节点 ${tunCheckRaw?.current || "-"}`}
            />
            {Array.isArray(tunCheckRaw?.issues) && tunCheckRaw.issues.length > 0 ? (
              <Alert
                showIcon
                type="warning"
                message="问题列表"
                description={(
                  <ul style={{marginBottom: 0, paddingLeft: 18}}>
                    {tunCheckRaw.issues.map((item, idx) => (
                      <li key={`tun-check-issue-${idx}`}>{String(item || "").trim()}</li>
                    ))}
                  </ul>
                )}
              />
            ) : null}
            {String(tunCheckRaw?.extras?.probe_guard_note || "").trim() ? (
              <Alert
                showIcon
                type="info"
                message="探测保护模式"
                description={String(tunCheckRaw?.extras?.probe_guard_note || "").trim()}
              />
            ) : null}
            {tunCheckMismatchRows.length > 0 ? (
              <Card
                size="small"
                title="证书主机名不匹配详情"
                extra={tunCheckRaw?.status?.openwrt ? (
                  <Button size="small" loading={tunDNSRepairLoading} onClick={repairOpenWrtDNSFromTunCheck}>
                    一键修复 OpenWrt DNS 污染
                  </Button>
                ) : null}
              >
                <Table
                  rowKey="key"
                  size="small"
                  pagination={false}
                  dataSource={tunCheckMismatchRows}
                  columns={[
                    {title: "目标域名", dataIndex: "host", width: 180},
                    {title: "证书主题", dataIndex: "cert_subject", width: 180},
                    {title: "证书DNS", dataIndex: "cert_dns_names", ellipsis: true},
                    {title: "耗时", dataIndex: "duration_ms", width: 90, render: (v) => `${toPositiveInt(v)} ms`},
                  ]}
                />
                <Typography.Paragraph style={{marginTop: 8, marginBottom: 0}} type="secondary">
                  出现该问题通常意味着域名解析链路异常或被污染（例如 Google 域名解析到了非 Google 证书站点）。
                </Typography.Paragraph>
              </Card>
            ) : null}
            {tunCheckDNSProbeRows.length > 0 ? (
              <Card size="small" title="异常域名 DNS 采样">
                <Table
                  rowKey="key"
                  size="small"
                  pagination={false}
                  dataSource={tunCheckDNSProbeRows}
                  columns={[
                    {title: "域名", dataIndex: "host", width: 180},
                    {title: "DNS服务器", dataIndex: "dns_server", width: 170},
                    {title: "查询协议", dataIndex: "network", width: 90},
                    {title: "解析结果", dataIndex: "ips", ellipsis: true},
                    {title: "状态", dataIndex: "ok", width: 90, render: (v) => v ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>},
                    {title: "错误", dataIndex: "error", ellipsis: true},
                    {title: "耗时", dataIndex: "duration_ms", width: 90, render: (v) => `${toPositiveInt(v)} ms`},
                  ]}
                />
              </Card>
            ) : null}
            <Card size="small" title="执行步骤">
              <Table
                rowKey={(row, idx) => `${row?.name || "step"}-${idx}`}
                size="small"
                pagination={false}
                dataSource={Array.isArray(tunCheckRaw?.steps) ? tunCheckRaw.steps : []}
                columns={[
                  {title: "步骤", dataIndex: "name", render: (v) => v || "-"},
                  {title: "状态", dataIndex: "status", width: 90, render: (v) => {
                    const text = String(v || "").toLowerCase();
                    if (text === "success") return <Tag color="green">成功</Tag>;
                    if (text === "failed") return <Tag color="red">失败</Tag>;
                    return <Tag>{v || "-"}</Tag>;
                  }},
                  {title: "耗时", dataIndex: "duration_ms", width: 120, render: (v) => `${toPositiveInt(v)} ms`},
                  {title: "信息", dataIndex: "message", render: (v) => v || "-"},
                  {title: "错误", dataIndex: "error", render: (v) => v || "-"},
                ]}
              />
            </Card>
            <Card size="small" title="原始结果(JSON)">
              <Typography.Paragraph copyable style={{whiteSpace: "pre-wrap", marginBottom: 0}}>
                {JSON.stringify(tunCheckRaw, null, 2)}
              </Typography.Paragraph>
            </Card>
          </Space>
        ) : (
          <Typography.Text type="secondary">暂无测试结果</Typography.Text>
        )}
      </Modal>

      <Modal title="配置备份与回滚" open={backupVisible} onCancel={() => setBackupVisible(false)} footer={null} width={960}>
        <Space style={{marginBottom: 12}} wrap>
          <Button onClick={loadBackups} loading={backupLoading}>刷新备份</Button>
          <Popconfirm title="确认回滚到最近一次备份？" onConfirm={() => rollbackBackup("")}>
            <Button danger loading={rollingBack}>回滚到最近备份</Button>
          </Popconfirm>
        </Space>
        {isMobile ? (
          <Space direction="vertical" style={{display: "flex"}} className="mobile-list">
            {(backupRows || []).map((row) => (
              <Card key={row.key} size="small">
                <Typography.Text strong>{row.name}</Typography.Text>
                <div style={{marginTop: 8}}>
                  <Typography.Text type="secondary">大小: {row.size} bytes</Typography.Text>
                  <br />
                  <Typography.Text type="secondary">时间: {formatDateTimeCST(row.mod_time)}</Typography.Text>
                </div>
                <Popconfirm title={`确认回滚到 ${row.name} ?`} onConfirm={() => rollbackBackup(row.name)}>
                  <Button style={{marginTop: 10}} danger size="small" loading={rollingBack}>回滚</Button>
                </Popconfirm>
              </Card>
            ))}
            {(backupRows || []).length === 0 ? (
              <Typography.Text type="secondary">暂无备份</Typography.Text>
            ) : null}
          </Space>
        ) : (
          <Table
            rowKey="key"
            loading={backupLoading}
            dataSource={backupRows}
            pagination={false}
            columns={[
              {title: "备份名", dataIndex: "name"},
              {title: "大小", dataIndex: "size", render: (v) => `${v} bytes`},
              {title: "时间", dataIndex: "mod_time", render: (v) => formatDateTimeCST(v)},
              {
                title: "操作",
                dataIndex: "name",
                render: (name) => (
                  <Popconfirm title={`确认回滚到 ${name} ?`} onConfirm={() => rollbackBackup(name)}>
                    <Button danger size="small" loading={rollingBack}>回滚</Button>
                  </Popconfirm>
                )
              }
            ]}
          />
        )}
      </Modal>
    </Layout>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
