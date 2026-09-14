"use strict";
"require view";
"require form";

var zh = {
  "NetQMon Agent": "NetQMon 代理",
  "Tune capture, batching, flow lifecycle, protocol probing, and counter sanity settings.":
    "调整采集、批处理、连接流生命周期、数据包采样和接口计数器校验设置。",
  Advanced: "高级",
  "Poll interval (ms)": "轮询间隔（毫秒）",
  "BPF flow map polling interval.": "BPF 连接流表轮询间隔。",
  "Batch interval (ms)": "批量发送间隔（毫秒）",
  "Telemetry batch submission interval.": "遥测数据批量提交间隔。",
  "Maximum flows": "最大连接流数",
  "Maximum concurrent tracked network flows.":
    "可同时跟踪的最大网络连接流数量。",
  "Retry buffer (seconds)": "重试缓冲（秒）",
  "Bounded in-memory retry queue window while the Controller is unavailable.":
    "Controller 不可用时内存重试队列保留窗口。",
  "TCP idle timeout (seconds)": "TCP 空闲超时（秒）",
  "Idle timeout before completing TCP flows.":
    "TCP 连接流完成前的空闲超时时间。",
  "UDP idle timeout (seconds)": "UDP 空闲超时（秒）",
  "Idle timeout before completing UDP flows.":
    "UDP 连接流完成前的空闲超时时间。",
  "Packet sampling": "数据包采样",
  "Capture bounded raw network payload for memory-only Collector DPI. Payload is never persisted.":
    "捕获有限原始网络载荷，仅用于 Collector 内存中的 DPI，不持久化。",
  "Packets per direction": "数据包采样包数",
  "Maximum sampled packets in each direction.":
    "每个方向最多采样的数据包数量。",
  "Sample bytes per packet": "每包数据包采样字节数",
  "Maximum bytes copied from one IP packet.": "从单个探测包复制的最大字节数。",
  "Sample bytes per flow": "每连接流数据包采样字节数",
  "Total sample byte budget shared by both directions.":
    "探测关联器为每条连接流保留的最大字节数。",
  "Interface counter sanity": "接口计数器校验",
  "Compare interface counters with captured flow bytes to detect degraded coverage.":
    "比较接口计数器和已采集连接流字节数，用于发现采集覆盖下降。",
  "Counter sanity minimum bytes": "计数器校验最小字节数",
  "Minimum interface byte delta before counter-gap warnings are considered.":
    "触发计数器差距告警前要求的最小接口字节变化量。",
  "Counter sanity max ratio": "计数器校验最大比例",
  "Warn when interface bytes exceed captured flow bytes by more than this ratio.":
    "当接口字节数超过已采集连接流字节数且比例高于此值时告警。",
  "Agent diagnostics": "代理诊断",
  "Expose internal agent diagnostics for troubleshooting.":
    "暴露代理内部诊断信息以便排障。",
  "Log level": "日志级别",
  "Controls agent stdout/stderr verbosity. Use Debug only during short troubleshooting sessions.":
    "控制代理 stdout/stderr 详细程度。Debug 仅建议在短时间排障时使用。",
  Error: "错误",
  Warning: "警告",
  Info: "信息",
  Debug: "调试",
  Trace: "跟踪",
  "Update channel": "更新渠道",
  Stable: "稳定版",
  Beta: "测试版",
  "Beta is reserved until beta release manifests are published.":
    "Beta 渠道保留，直到发布 beta release manifest。",
};

function isZh() {
  var lang = (
    (L.env && L.env.lang) ||
    document.documentElement.lang ||
    ""
  ).toLowerCase();
  return lang.indexOf("zh") === 0;
}

function t(key) {
  return isZh() && zh[key] ? zh[key] : _(key);
}

function numberOption(section, name, title, description, def, min, max) {
  var o = section.option(form.Value, name, title);
  o.default = String(def);
  o.datatype = max ? "range(%d,%d)".format(min, max) : "min(%d)".format(min);
  o.rmempty = false;
  o.description = description;
  return o;
}

return view.extend({
  render: function () {
    var m, s, o;

    m = new form.Map("netqmon", t("NetQMon Agent"));
    m.description = t(
      "Tune capture, batching, flow lifecycle, protocol probing, and counter sanity settings.",
    );

    s = m.section(form.NamedSection, "main", "agent", t("Advanced"));
    s.addremove = false;

    numberOption(
      s,
      "poll_interval_ms",
      t("Poll interval (ms)"),
      t("BPF flow map polling interval."),
      1000,
      1,
    );
    numberOption(
      s,
      "batch_interval_ms",
      t("Batch interval (ms)"),
      t("Telemetry batch submission interval."),
      1000,
      1,
    );
    numberOption(
      s,
      "max_flows",
      t("Maximum flows"),
      t("Maximum concurrent tracked network flows."),
      65536,
      1,
    );
    numberOption(
      s,
      "retry_buffer_seconds",
      t("Retry buffer (seconds)"),
      t("Legacy retry window retained for configuration compatibility."),
      60,
      1,
    );
    numberOption(
      s,
      "telemetry_retry_buffer_bytes",
      t("Retry buffer (bytes)"),
      t(
        "Maximum encoded telemetry bytes retained while the Controller is unavailable; oldest batches are dropped first.",
      ),
      8388608,
      1,
    );

    numberOption(
      s,
      "tcp_idle_timeout_seconds",
      t("TCP idle timeout (seconds)"),
      t("Idle timeout before completing TCP flows."),
      120,
      1,
    );
    numberOption(
      s,
      "udp_idle_timeout_seconds",
      t("UDP idle timeout (seconds)"),
      t("Idle timeout before completing UDP flows."),
      30,
      1,
    );

    o = s.option(form.Flag, "sample_enabled", t("Packet sampling"));
    o.default = "1";
    o.rmempty = false;
    o.description = t(
      "Capture bounded raw network payload for memory-only Collector DPI. Payload is never persisted.",
    );

    numberOption(
      s,
      "sample_max_packets_per_direction",
      t("Packets per direction"),
      t("Maximum sampled packets in each direction."),
      4,
      1,
      32,
    );
    numberOption(
      s,
      "sample_max_bytes_per_packet",
      t("Sample bytes per packet"),
      t("Maximum bytes copied from one IP packet."),
      1024,
      1,
      4096,
    );
    numberOption(
      s,
      "sample_max_bytes_per_flow",
      t("Sample bytes per flow"),
      t("Total sample byte budget shared by both directions."),
      4096,
      1,
      65536,
    );

    o = s.option(
      form.Flag,
      "interface_counter_sanity_enabled",
      t("Interface counter sanity"),
    );
    o.default = "1";
    o.rmempty = false;
    o.description = t(
      "Compare interface counters with captured flow bytes to detect degraded coverage.",
    );

    numberOption(
      s,
      "interface_counter_min_bytes",
      t("Counter sanity minimum bytes"),
      t(
        "Minimum interface byte delta before counter-gap warnings are considered.",
      ),
      65536,
      1,
    );
    numberOption(
      s,
      "interface_counter_max_unaccounted_ratio",
      t("Counter sanity max ratio"),
      t(
        "Warn when interface bytes exceed captured flow bytes by more than this ratio.",
      ),
      4,
      1,
    );

    o = s.option(form.Flag, "diagnostics_enabled", t("Agent diagnostics"));
    o.default = "0";
    o.rmempty = false;
    o.description = t("Expose internal agent diagnostics for troubleshooting.");

    o = s.option(form.ListValue, "log_level", t("Log level"));
    o.value("error", t("Error"));
    o.value("warn", t("Warning"));
    o.value("info", t("Info"));
    o.value("debug", t("Debug"));
    o.value("trace", t("Trace"));
    o.default = "info";
    o.rmempty = false;
    o.description = t(
      "Controls agent stdout/stderr verbosity. Use Debug only during short troubleshooting sessions.",
    );

    o = s.option(form.ListValue, "update_channel", t("Update channel"));
    o.value("stable", t("Stable"));
    o.value("beta", t("Beta"));
    o.default = "stable";
    o.rmempty = false;
    o.description = t(
      "Beta is reserved until beta release manifests are published.",
    );

    return m.render();
  },
});
