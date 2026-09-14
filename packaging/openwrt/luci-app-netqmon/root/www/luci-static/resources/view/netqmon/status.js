"use strict";
"require view";
"require rpc";
"require ui";
"require poll";

var callStatus = rpc.declare({
  object: "netqmon",
  method: "status",
  expect: { "": {} },
});

var callDoctor = rpc.declare({
  object: "netqmon",
  method: "doctor",
  expect: { "": {} },
});

var callService = rpc.declare({
  object: "netqmon",
  method: "service",
  params: ["action"],
  expect: { "": {} },
});

var zh = {
  "Not running": "未运行",
  "%dd %dh %dm": "%d天 %d小时 %d分钟",
  "%dh %dm": "%d小时 %d分钟",
  "%dm": "%d分钟",
  "Doctor has not been run from this page yet.": "尚未从此页面运行诊断。",
  "Agent state": "代理状态",
  "Agent version": "代理版本",
  Uptime: "运行时间",
  PID: "PID",
  "Observation interfaces": "观测接口",
  "Controller URL": "控制器 URL",
  "Last startup error": "最近启动错误",
  "Service action failed": "服务操作失败",
  "NetQMon Agent Status": "NetQMon 代理状态",
  Start: "启动",
  Stop: "停止",
  Restart: "重启",
  "Starting...": "正在启动...",
  "Stopping...": "正在停止...",
  "Restarting...": "正在重启...",
  "Running doctor...": "正在运行诊断...",
  "Doctor reported a failure.": "诊断报告失败。",
  "Run Doctor": "运行诊断",
  Doctor: "诊断",
  unknown: "未知",
  running: "运行中",
  stopped: "已停止",
  disabled: "已禁用",
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

function displayValue(value) {
  return value && zh[value] ? t(value) : value;
}

function formatUptime(seconds) {
  seconds = Number(seconds || 0);
  if (!seconds) return t("Not running");

  var days = Math.floor(seconds / 86400);
  var hours = Math.floor((seconds % 86400) / 3600);
  var minutes = Math.floor((seconds % 3600) / 60);

  if (days) return t("%dd %dh %dm").format(days, hours, minutes);
  if (hours) return t("%dh %dm").format(hours, minutes);
  return t("%dm").format(minutes);
}

function row(label, value) {
  return E("tr", {}, [
    E("th", { class: "left", style: "width: 220px" }, label),
    E("td", {}, value || "-"),
  ]);
}

function formatInterfaces(status) {
  var interfaces = Array.isArray(status.interfaces) ? status.interfaces : [];

  if (!interfaces.length && status.interface) interfaces = [status.interface];

  return interfaces.length ? interfaces.join(", ") : "-";
}

return view.extend({
  load: function () {
    return callStatus();
  },

  render: function (data) {
    var table = E("table", { class: "table" });
    var doctorOutput = E(
      "pre",
      { class: "cbi-section", style: "white-space: pre-wrap" },
      t("Doctor has not been run from this page yet."),
    );
    var serviceButtons = [];
    var pendingAction = null;

    var pendingLabels = {
      start: t("Starting..."),
      stop: t("Stopping..."),
      restart: t("Restarting..."),
    };

    function renderStatus(status) {
      table.innerHTML = "";
      table.appendChild(
        row(t("Agent state"), displayValue(status.state || "unknown")),
      );
      table.appendChild(
        row(t("Agent version"), displayValue(status.version || "unknown")),
      );
      table.appendChild(row(t("Uptime"), formatUptime(status.uptime)));
      table.appendChild(row(t("PID"), status.pid ? String(status.pid) : "-"));
      table.appendChild(
        row(t("Observation interfaces"), formatInterfaces(status)),
      );
      table.appendChild(row(t("Controller URL"), status.controller_url || "-"));
      table.appendChild(row(t("Last startup error"), status.last_error || "-"));
    }

    function refreshStatus() {
      return callStatus().then(renderStatus);
    }

    function updateServiceButtons() {
      for (var i = 0; i < serviceButtons.length; i++) {
        var button = serviceButtons[i];
        button.disabled = pendingAction !== null;
        button.textContent =
          pendingAction === button.getAttribute("data-action")
            ? pendingLabels[pendingAction]
            : button.getAttribute("data-label");
        button.classList.toggle(
          "spinning",
          pendingAction === button.getAttribute("data-action"),
        );
      }
    }

    function serviceButton(action, label, css) {
      var button = E(
        "button",
        {
          class: "btn %s".format(css || "cbi-button"),
          "data-action": action,
          "data-label": label,
          click: function () {
            pendingAction = action;
            updateServiceButtons();

            return callService(action)
              .then(function (result) {
                if (!result.ok)
                  ui.addNotification(
                    null,
                    E(
                      "p",
                      {},
                      result.error ||
                        result.output ||
                        t("Service action failed"),
                    ),
                    "danger",
                  );
                return refreshStatus();
              })
              .then(
                function () {
                  pendingAction = null;
                  updateServiceButtons();
                },
                function (err) {
                  pendingAction = null;
                  updateServiceButtons();
                  throw err;
                },
              );
          },
        },
        label,
      );

      serviceButtons.push(button);
      return button;
    }

    renderStatus(data || {});
    poll.add(refreshStatus);

    return E("div", { class: "cbi-map" }, [
      E("h2", {}, t("NetQMon Agent Status")),
      E("div", { class: "cbi-section" }, [
        table,
        E("div", { class: "cbi-page-actions" }, [
          serviceButton("start", t("Start"), "cbi-button-apply"),
          " ",
          serviceButton("stop", t("Stop"), "cbi-button-remove"),
          " ",
          serviceButton("restart", t("Restart"), "cbi-button-reload"),
          " ",
          E(
            "button",
            {
              class: "btn cbi-button-action",
              click: function () {
                doctorOutput.textContent = t("Running doctor...");
                return callDoctor().then(function (result) {
                  doctorOutput.textContent = result.output || "";
                  if (!result.ok)
                    ui.addNotification(
                      null,
                      E("p", {}, t("Doctor reported a failure.")),
                      "warning",
                    );
                  return refreshStatus();
                });
              },
            },
            t("Run Doctor"),
          ),
        ]),
      ]),
      E("h3", {}, t("Doctor")),
      doctorOutput,
    ]);
  },
});
