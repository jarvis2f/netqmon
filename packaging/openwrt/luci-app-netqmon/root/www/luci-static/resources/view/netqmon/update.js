"use strict";
"require view";
"require rpc";
"require ui";

var callUpdateCheck = rpc.declare({
  object: "netqmon",
  method: "update_check",
  expect: { "": {} },
});

var callUpdateStatus = rpc.declare({
  object: "netqmon",
  method: "update_status",
  expect: { "": {} },
});

var callUpdateApply = rpc.declare({
  object: "netqmon",
  method: "update_apply",
  expect: { "": {} },
});

var zh = {
  "No update check has been run yet.": "尚未运行更新检查。",
  "Current version": "当前版本",
  "Latest version": "最新版本",
  "Update channel": "更新渠道",
  Architecture: "架构",
  "Last check": "上次检查",
  "NetQMon Agent Update": "NetQMon 代理更新",
  "Checking for updates...": "正在检查更新...",
  "Update check completed.": "更新检查完成。",
  "Update check failed.": "更新检查失败。",
  "Check for Updates": "检查更新",
  "Updating agent...": "正在更新代理...",
  "Agent updated and verified.": "代理已更新并通过验证。",
  "Agent update failed.": "代理更新失败。",
  "Update Agent": "更新代理",
  "Update Log": "更新日志",
  unknown: "未知",
  stable: "稳定版",
  beta: "测试版",
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

function row(label, value) {
  return E("tr", {}, [
    E("th", { class: "left", style: "width: 220px" }, label),
    E("td", {}, value || "-"),
  ]);
}

return view.extend({
  load: function () {
    return callUpdateStatus();
  },

  render: function (data) {
    var table = E("table", { class: "table" });
    var log = E(
      "pre",
      { class: "cbi-section", style: "white-space: pre-wrap" },
      t("No update check has been run yet."),
    );
    var last = {};

    function renderResult(result) {
      last = result || {};
      table.innerHTML = "";
      table.appendChild(
        row(
          t("Current version"),
          displayValue(last.current_version || "unknown"),
        ),
      );
      table.appendChild(
        row(
          t("Latest version"),
          displayValue(last.latest_version || "unknown"),
        ),
      );
      table.appendChild(
        row(t("Update channel"), displayValue(last.channel || "stable")),
      );
      table.appendChild(row(t("Architecture"), last.architecture || "-"));
      table.appendChild(row(t("Last check"), last.last_check || "-"));
      if (!last.ok && last.error) log.textContent = last.error;
    }

    function runUpdateAction(message, action, successMessage, failureMessage) {
      log.textContent = message;
      return action()
        .then(function (result) {
          renderResult(result);
          log.textContent = result.ok
            ? successMessage
            : result.error || failureMessage;
          if (!result.ok)
            ui.addNotification(null, E("p", {}, log.textContent), "danger");
        })
        .catch(function (error) {
          log.textContent =
            error && error.message ? error.message : failureMessage;
          ui.addNotification(null, E("p", {}, log.textContent), "danger");
        });
    }

    renderResult(data || last);

    return E("div", { class: "cbi-map" }, [
      E("h2", {}, t("NetQMon Agent Update")),
      E("div", { class: "cbi-section" }, [
        table,
        E("div", { class: "cbi-page-actions" }, [
          E(
            "button",
            {
              class: "btn cbi-button-action",
              click: function () {
                return runUpdateAction(
                  t("Checking for updates..."),
                  callUpdateCheck,
                  t("Update check completed."),
                  t("Update check failed."),
                );
              },
            },
            t("Check for Updates"),
          ),
          " ",
          E(
            "button",
            {
              class: "btn cbi-button-apply",
              click: function () {
                return runUpdateAction(
                  t("Updating agent..."),
                  callUpdateApply,
                  t("Agent updated and verified."),
                  t("Agent update failed."),
                );
              },
            },
            t("Update Agent"),
          ),
        ]),
      ]),
      E("h3", {}, t("Update Log")),
      log,
    ]);
  },
});
