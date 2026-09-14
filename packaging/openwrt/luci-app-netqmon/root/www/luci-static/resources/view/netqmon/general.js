"use strict";
"require view";
"require form";
"require uci";
"require rpc";

var callNetworkDevices = rpc.declare({
  object: "luci-rpc",
  method: "getNetworkDevices",
  expect: { "": {} },
});

var zh = {
  "NetQMon Agent": "NetQMon 代理",
  "Configure the OpenWrt agent connection to the NetQMon Controller.":
    "配置 OpenWrt 代理连接到 NetQMon 控制器。",
  General: "常规",
  Enabled: "启用",
  "Observation interfaces": "观测接口",
  "Interfaces where the agent attaches TC eBPF telemetry hooks. Keep them in priority order; the first interface is also retained for compatibility with older agents.":
    "代理挂载 TC eBPF 遥测钩子的接口。请按优先级排序；首个接口也会保留给旧版代理兼容使用。",
  "Add between 1 and 32 unique interface names. Each name must contain 1 to 15 characters and must not contain a slash or NUL.":
    "请添加 1 到 32 个不重复的接口名称。每个名称必须为 1 到 15 个字符，且不能包含斜杠或 NUL。",
  "Controller URL": "控制器 URL",
  "Absolute HTTP URL of the NetQMon Collector ingestion endpoint.":
    "NetQMon Collector 数据接收端点的绝对 HTTP URL。",
  "Controller URL must be an absolute HTTP or HTTPS URL.":
    "控制器 URL 必须是绝对 HTTP 或 HTTPS URL。",
  Token: "令牌",
  "Enrollment token configured on the Controller. Existing values are hidden.":
    "控制器上配置的注册令牌。现有值会被隐藏。",
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

function normalizeInterfaces(value) {
  if (Array.isArray(value)) return value;
  return value ? [value] : [];
}

function validateInterfaceName(name) {
  var str = String(name || "");
  return (
    str.length >= 1 &&
    str.length <= 15 &&
    str.indexOf("/") === -1 &&
    str.indexOf("\0") === -1
  );
}

function validateInterfaces(value) {
  var interfaces = normalizeInterfaces(value);
  var seen = {};

  if (interfaces.length < 1 || interfaces.length > 32) return false;

  for (var i = 0; i < interfaces.length; i++) {
    var name = String(interfaces[i] || "");
    if (!validateInterfaceName(name) || seen[name]) return false;
    seen[name] = true;
  }

  return true;
}

return view.extend({
  load: function () {
    return callNetworkDevices();
  },

  render: function (devices) {
    var m, s, o;

    m = new form.Map("netqmon", t("NetQMon Agent"));
    m.description = t(
      "Configure the OpenWrt agent connection to the NetQMon Controller.",
    );

    s = m.section(form.NamedSection, "main", "agent", t("General"));
    s.addremove = false;

    o = s.option(form.Flag, "enabled", t("Enabled"));
    o.default = "1";
    o.rmempty = false;

    o = s.option(form.DynamicList, "interfaces", t("Observation interfaces"));
    o.default = ["br-lan"];
    o.rmempty = false;
    o.forcewrite = true;
    o.description = t(
      "Interfaces where the agent attaches TC eBPF telemetry hooks. Keep them in priority order; the first interface is also retained for compatibility with older agents.",
    );
    o.cfgvalue = function (section_id) {
      var configured = normalizeInterfaces(
        uci.get("netqmon", section_id, "interfaces"),
      );
      var legacy;

      if (configured.length) return configured;

      legacy = uci.get("netqmon", section_id, "interface");
      return legacy ? [legacy] : this.default;
    };
    o.write = function (section_id, value) {
      var interfaces = normalizeInterfaces(value);

      uci.set("netqmon", section_id, "interfaces", interfaces);
      uci.set("netqmon", section_id, "interface", interfaces[0]);
    };
    o.validate = function (section_id, value) {
      if (value == null || value === "") return true;

      if (Array.isArray(value))
        return validateInterfaces(value)
          ? true
          : t(
              "Add between 1 and 32 unique interface names. Each name must contain 1 to 15 characters and must not contain a slash or NUL.",
            );

      return validateInterfaceName(value)
        ? true
        : t(
            "Add between 1 and 32 unique interface names. Each name must contain 1 to 15 characters and must not contain a slash or NUL.",
          );
    };
    o.isValid = function (section_id) {
      var element = this.getUIElement(section_id);
      return (
        (!element || element.isValid()) &&
        validateInterfaces(this.formvalue(section_id))
      );
    };
    o.getValidationError = function (section_id) {
      var element = this.getUIElement(section_id);
      if (!validateInterfaces(this.formvalue(section_id)))
        return t(
          "Add between 1 and 32 unique interface names. Each name must contain 1 to 15 characters and must not contain a slash or NUL.",
        );
      return (
        (element && element.getValidationError()) ||
        t(
          "Add between 1 and 32 unique interface names. Each name must contain 1 to 15 characters and must not contain a slash or NUL.",
        )
      );
    };

    Object.keys(devices || {})
      .sort()
      .forEach(function (name) {
        if (
          name &&
          name.length <= 15 &&
          name.indexOf("/") === -1 &&
          name.indexOf("\0") === -1
        )
          o.value(name);
      });

    o = s.option(form.Value, "controller_url", t("Controller URL"));
    o.default = "http://127.0.0.1:8090";
    o.rmempty = false;
    o.description = t(
      "Absolute HTTP URL of the NetQMon Collector ingestion endpoint.",
    );
    o.validate = function (section_id, value) {
      if (!/^https?:\/\/[^/]+/.test(value || ""))
        return t("Controller URL must be an absolute HTTP or HTTPS URL.");
      return true;
    };

    o = s.option(form.Value, "token", t("Token"));
    o.password = true;
    o.rmempty = true;
    o.description = t(
      "Enrollment token configured on the Controller. Existing values are hidden.",
    );

    return m.render();
  },
});
