/*
 * skip-loopback-proxy.js
 * ------------------------------------------------------------------
 * 目的：抓包已经通了（系统代理 -> Burp），但 App 里有个请求目标是“回环地址”
 *       （127.0.0.1 / localhost / ::1 等），它也被一起转发进了 Burp，导致出错。
 *       本脚本只做一件事：让“回环地址”的请求直连，其余请求照常走系统代理(Burp)。
 *
 * 原理：
 *   不替换 App 的任何东西，只 Hook 系统“默认 ProxySelector”的 select()：
 *     - 目标是回环地址 -> 返回 NO_PROXY(直连)，不进 Burp；
 *     - 其它地址      -> 调用原始 select()，保持原来的系统代理行为不变。
 *   OkHttp / HttpURLConnection 默认都走这个 ProxySelector，所以一处生效、全局生效。
 *
 * 运行：
 *   frida -U -f <包名> -l skip-loopback-proxy.js
 *   或：frida -U <包名/进程名> -l skip-loopback-proxy.js
 */

'use strict';

Java.perform(function () {
    var ProxySelector = Java.use('java.net.ProxySelector');
    var Proxy = Java.use('java.net.Proxy');
    var ArrayList = Java.use('java.util.ArrayList');

    function isLoopbackHost(host) {
        if (host === null || host === undefined) {
            return false;
        }
        var h = ('' + host).toLowerCase().trim();
        if (h.length > 1 && h.charAt(0) === '[' && h.charAt(h.length - 1) === ']') {
            h = h.substring(1, h.length - 1); // 去掉 IPv6 字面量的中括号 [::1]
        }
        if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') return true;
        if (h.indexOf('127.') === 0) return true;            // 127.0.0.0/8
        if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
        if (h === '0.0.0.0' || h === '::' || h === '0:0:0:0:0:0:0:0') return true;
        return false;
    }

    // 动态拿到“当前默认 ProxySelector”的真实类名再去 Hook，避免不同 Android 版本类名不一致。
    var defaultSelector = ProxySelector.getDefault();
    if (defaultSelector === null) {
        console.log('[skip-loopback] 默认 ProxySelector 为 null，说明当前没走系统代理，无需处理。');
        return;
    }

    var clsName = defaultSelector.getClass().getName();
    console.log('[skip-loopback] 默认 ProxySelector 类: ' + clsName);

    var SelectorClass;
    try {
        SelectorClass = Java.use(clsName);
    } catch (e) {
        console.log('[skip-loopback] 无法加载 ' + clsName + '，Hook 失败: ' + e);
        return;
    }

    if (SelectorClass.select === undefined) {
        console.log('[skip-loopback] ' + clsName + ' 没有 select 方法，Hook 失败。');
        return;
    }

    SelectorClass.select.overloads.forEach(function (ov) {
        ov.implementation = function (uri) {
            var host = null;
            try {
                host = uri.getHost();
            } catch (e) {}

            if (isLoopbackHost(host)) {
                // 回环地址：返回直连，不进 Burp。
                var list = ArrayList.$new();
                list.add(Proxy.NO_PROXY.value);
                console.log('[skip-loopback] DIRECT  -> ' + host + '  (回环地址，跳过代理)');
                return list;
            }
            // 其它地址：保持原行为（系统代理 -> Burp）。
            return ov.call(this, uri);
        };
    });

    console.log('[skip-loopback] 完成：回环地址将直连，其余请求仍走系统代理(Burp)。');
});
