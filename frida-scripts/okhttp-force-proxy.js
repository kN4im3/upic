/*
 * okhttp-force-proxy.js
 * ------------------------------------------------------------------
 * 强制让 Android App 内部的 OkHttp(okhttp3) 走指定代理，方便抓包。
 *
 * 适用场景：
 *   - App 默认不读取系统 WiFi 代理（很多 App 写死 Proxy.NO_PROXY，
 *     或者使用自定义 ProxySelector / DNS，导致设置系统代理后抓不到包）。
 *   - 通过 Hook OkHttpClient.Builder，给每一个客户端注入一个自定义的
 *     ProxySelector，把流量统一转发到你的抓包工具（Charles / mitmproxy / Burp）。
 *   - 自动跳过本地回环地址（127.0.0.0/8、localhost、::1 等），
 *     避免 App 内部访问本机服务（如 WebView 本地服务、健康检查）时
 *     被错误地导到代理上导致连接失败。
 *
 * 使用方法：
 *   1. 修改下面的 PROXY_HOST / PROXY_PORT 为你抓包机器的 IP 和端口。
 *      注意：在手机上 127.0.0.1 指的是手机自己，所以这里要填运行抓包
 *      工具那台电脑在局域网里的 IP（例如 192.168.1.10）。
 *   2. 运行：
 *        frida -U -f <包名> -l okhttp-force-proxy.js
 *      或附加到已运行进程：
 *        frida -U <包名或进程名> -l okhttp-force-proxy.js
 *
 * 说明：
 *   - 优先使用 ProxySelector 方式，这样可以按 host 决定“走代理”还是
 *     “直连”，从而实现“跳过本地回环”。
 *   - 同时把 Builder.proxy() 设置的写死代理清掉（置为 null），
 *     否则 OkHttp 会优先用 proxy 字段而忽略 proxySelector。
 */

'use strict';

// ====================== 配置区 ======================
var PROXY_HOST = '192.168.1.10'; // TODO: 改成你抓包电脑的局域网 IP
var PROXY_PORT = 8888;           // TODO: 改成你抓包工具的端口（Charles 默认 8888 / mitmproxy 8080 / Burp 8080）
var VERBOSE = true;              // 是否打印每一次代理选择日志
// ===================================================

Java.perform(function () {
    var Proxy = Java.use('java.net.Proxy');
    var ProxyType = Java.use('java.net.Proxy$Type');
    var InetSocketAddress = Java.use('java.net.InetSocketAddress');
    var ProxySelector = Java.use('java.net.ProxySelector');
    var ArrayList = Java.use('java.util.ArrayList');

    function log(msg) {
        if (VERBOSE) {
            console.log('[okhttp-proxy] ' + msg);
        }
    }

    /**
     * 判断 host 是否为本地回环地址 / 本机地址，这类地址需要直连而不走代理。
     */
    function isLoopbackHost(host) {
        if (host === null || host === undefined) {
            return false;
        }
        var h = ('' + host).toLowerCase().trim();
        // 去掉 IPv6 字面量两侧的中括号，例如 [::1]
        if (h.length > 1 && h.charAt(0) === '[' && h.charAt(h.length - 1) === ']') {
            h = h.substring(1, h.length - 1);
        }
        if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') {
            return true;
        }
        // IPv4 回环段 127.0.0.0/8
        if (h.indexOf('127.') === 0) {
            return true;
        }
        // 0.0.0.0 / :: 通常也指向本机，直连更安全
        if (h === '0.0.0.0' || h === '::' || h === '0:0:0:0:0:0:0:0') {
            return true;
        }
        // IPv6 回环
        if (h === '::1' || h === '0:0:0:0:0:0:0:1') {
            return true;
        }
        return false;
    }

    // 注意：不要在这里预先创建 Proxy/InetSocketAddress 实例再缓存到全局变量。
    // select()/build() 会在 App 的网络线程上被回调，跨线程使用之前缓存的
    // Java 实例引用会失效，导致 JNI 崩溃（表现为 "Process terminated"）。
    // 正确做法是：在回调内部、当前线程上现场创建这些对象。

    // 自定义 ProxySelector：本地回环走直连，其余走指定代理。
    var ForceProxySelector = Java.registerClass({
        name: 'com.frida.ForceProxySelector',
        superClass: ProxySelector,
        methods: {
            select: function (uri) {
                // 全部在当前(回调)线程内现场创建，避免使用失效的跨线程引用。
                var list = ArrayList.$new();
                var host = null;
                try {
                    host = uri.getHost();
                } catch (e) {}

                try {
                    if (isLoopbackHost(host)) {
                        list.add(Proxy.NO_PROXY.value); // 直连
                        log('DIRECT  -> ' + host + '  (本地回环，跳过代理)');
                    } else {
                        var addr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
                        var p = Proxy.$new(ProxyType.HTTP.value, addr);
                        list.add(p);
                        log('PROXY   -> ' + host + '  via ' + PROXY_HOST + ':' + PROXY_PORT);
                    }
                } catch (e) {
                    // 兜底：出错时直连，避免影响 App 正常运行。
                    log('select() 构造代理失败，改为直连: ' + e);
                    try { list.add(Proxy.NO_PROXY.value); } catch (e2) {}
                }
                return list;
            },
            connectFailed: function (uri, sa, ioe) {
                log('connectFailed: ' + uri + ' (' + ioe + ')');
            }
        }
    });

    // selectorInstance 会在不同线程的 build() 回调里反复使用，必须 retain，
    // 否则同样会因为跨线程引用失效而崩溃。
    var selectorInstance = Java.retain(ForceProxySelector.$new());

    var Builder;
    try {
        Builder = Java.use('okhttp3.OkHttpClient$Builder');
    } catch (e) {
        console.log('[okhttp-proxy] 未找到 okhttp3.OkHttpClient$Builder，' +
            'App 可能没用 OkHttp 或类名被混淆。错误: ' + e);
        return;
    }

    // 只 Hook build()，把侵入性降到最低：
    //   - 这里不再单独 Hook proxy()/proxySelector() 两个 setter，避免日志刷屏，
    //     也减少对 App 启动流程的干扰。
    //   - build() 是 Builder 的最后一步，在这里设置一定能覆盖 App 之前的设置。
    //   - this.proxy(null)/this.proxySelector(...) 此时调用的是“原始 setter”
    //     （它们没有被 Hook），不存在递归。
    //   - this.build() 在 build 的 implementation 内调用，Frida 会自动转发到
    //     “原始 build”，不会无限递归。
    try {
        Builder.build.implementation = function () {
            try {
                this.proxy(null);                 // 清掉 App 写死的代理，否则会优先于 proxySelector
            } catch (e) {
                log('build() 中清理 proxy 失败(可忽略): ' + e);
            }
            try {
                this.proxySelector(selectorInstance);
            } catch (e) {
                log('build() 中注入 proxySelector 失败: ' + e);
            }
            log('OkHttpClient.build() -> 已注入 ForceProxySelector');
            return this.build();
        };
    } catch (e) {
        console.log('[okhttp-proxy] Hook Builder.build 失败: ' + e);
    }

    console.log('[okhttp-proxy] Hook 完成，所有 OkHttp 流量(非本地回环)将转发到 ' +
        PROXY_HOST + ':' + PROXY_PORT);
});
