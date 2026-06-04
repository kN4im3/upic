/*
 * Force OkHttp traffic through a proxy with loopback bypass.
 *
 * Usage:
 *   1. Edit PROXY_HOST / PROXY_PORT below.
 *   2. Run:
 *      frida -U -f your.package.name -l frida-okhttp-proxy-hook.js --no-pause
 *
 * Notes:
 *   - This script uses a ProxySelector instead of a fixed Proxy so each
 *     request can decide whether to use the proxy.
 *   - Loopback hosts such as localhost, 127.0.0.0/8, ::1 and common Android
 *     emulator loopback aliases are returned as Proxy.NO_PROXY.
 *   - It targets normal OkHttp package names. If the app shades/relocates
 *     OkHttp, add the relocated Builder class name to OKHTTP3_BUILDER_CLASSES.
 */

'use strict';

const CONFIG = {
  PROXY_HOST: '127.0.0.1',
  PROXY_PORT: 8080,

  // Supported values: HTTP, SOCKS
  PROXY_TYPE: 'HTTP',

  LOG_EACH_REQUEST: true,

  // Exact host bypass list. Keep these narrow so LAN/private hosts still proxy.
  EXTRA_BYPASS_HOSTS: [
    '0.0.0.0',
    '10.0.2.2', // Android emulator alias for host loopback.
    '10.0.3.2'  // Genymotion alias for host loopback.
  ]
};

const OKHTTP3_BUILDER_CLASSES = [
  'okhttp3.OkHttpClient$Builder'
];

function log(message) {
  console.log('[okhttp-proxy] ' + message);
}

function normalizeHost(host) {
  if (host === null || host === undefined) {
    return '';
  }

  let value = String(host).trim().toLowerCase();
  if (value.length === 0) {
    return '';
  }

  if (value[0] === '[' && value[value.length - 1] === ']') {
    value = value.substring(1, value.length - 1);
  }

  const zoneIndex = value.indexOf('%');
  if (zoneIndex !== -1) {
    value = value.substring(0, zoneIndex);
  }

  return value;
}

function isIPv4Loopback(host) {
  const parts = host.split('.');
  if (parts.length !== 4) {
    return false;
  }

  for (let i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) {
      return false;
    }

    const octet = parseInt(parts[i], 10);
    if (octet < 0 || octet > 255) {
      return false;
    }
  }

  return parseInt(parts[0], 10) === 127;
}

function isIPv6Loopback(host) {
  return host === '::1' || host === '0:0:0:0:0:0:0:1';
}

function shouldBypassProxy(rawHost) {
  const host = normalizeHost(rawHost);
  if (host.length === 0) {
    return false;
  }

  if (host === 'localhost' || host.endsWith('.localhost')) {
    return true;
  }

  if (isIPv4Loopback(host) || isIPv6Loopback(host)) {
    return true;
  }

  return CONFIG.EXTRA_BYPASS_HOSTS.indexOf(host) !== -1;
}

function getHostFromUri(uri) {
  if (uri === null || uri === undefined) {
    return '';
  }

  try {
    const host = uri.getHost();
    if (host !== null) {
      return String(host);
    }
  } catch (_) {
    // Fall through to a conservative string parse below.
  }

  const text = String(uri.toString());
  const match = text.match(/^[a-z][a-z0-9+.-]*:\/\/(\[[^\]]+\]|[^/:?#]+)/i);
  return match ? match[1] : '';
}

Java.perform(function () {
  const ArrayList = Java.use('java.util.ArrayList');
  const InetSocketAddress = Java.use('java.net.InetSocketAddress');
  const Proxy = Java.use('java.net.Proxy');
  const ProxySelector = Java.use('java.net.ProxySelector');
  const ProxyType = Java.use('java.net.Proxy$Type');

  const proxyType = ProxyType[CONFIG.PROXY_TYPE].value;
  const proxyAddress = InetSocketAddress.createUnresolved(
    CONFIG.PROXY_HOST,
    CONFIG.PROXY_PORT
  );
  const forcedProxy = Proxy.$new(proxyType, proxyAddress);
  const directProxy = Proxy.NO_PROXY.value;

  function proxyListFor(uri) {
    const host = getHostFromUri(uri);
    const proxies = ArrayList.$new();

    if (shouldBypassProxy(host)) {
      proxies.add(directProxy);
      if (CONFIG.LOG_EACH_REQUEST) {
        log('DIRECT  ' + uri + ' host=' + host);
      }
      return proxies;
    }

    proxies.add(forcedProxy);
    if (CONFIG.LOG_EACH_REQUEST) {
      log('PROXY   ' + uri + ' host=' + host + ' -> ' +
        CONFIG.PROXY_HOST + ':' + CONFIG.PROXY_PORT);
    }
    return proxies;
  }

  const ForcedProxySelector = Java.registerClass({
    name: 'com.frida.okhttp.ForcedProxySelector',
    superClass: ProxySelector,
    methods: {
      select: [{
        returnType: 'java.util.List',
        argumentTypes: ['java.net.URI'],
        implementation: function (uri) {
          return proxyListFor(uri);
        }
      }],
      connectFailed: [{
        returnType: 'void',
        argumentTypes: [
          'java.net.URI',
          'java.net.SocketAddress',
          'java.io.IOException'
        ],
        implementation: function (uri, address, exception) {
          log('connectFailed uri=' + uri + ' address=' + address +
            ' error=' + exception);
        }
      }]
    }
  });

  const forcedSelector = ForcedProxySelector.$new();

  function hookOkHttp3Builder(builderClassName) {
    let Builder;
    try {
      Builder = Java.use(builderClassName);
    } catch (_) {
      return false;
    }

    log('hooking ' + builderClassName);

    let proxyMethod = null;
    let proxySelectorMethod = null;

    try {
      proxyMethod = Builder.proxy.overload('java.net.Proxy');
      proxyMethod.implementation = function (_proxy) {
        log(builderClassName + '.proxy(...) intercepted; using ProxySelector');
        const result = proxyMethod.call(this, null);
        if (proxySelectorMethod !== null) {
          proxySelectorMethod.call(this, forcedSelector);
        }
        return result;
      };
    } catch (error) {
      log(builderClassName + '.proxy hook skipped: ' + error);
    }

    try {
      proxySelectorMethod =
        Builder.proxySelector.overload('java.net.ProxySelector');
      proxySelectorMethod.implementation = function (_selector) {
        log(builderClassName + '.proxySelector(...) replaced');
        return proxySelectorMethod.call(this, forcedSelector);
      };
    } catch (error) {
      log(builderClassName + '.proxySelector hook skipped: ' + error);
    }

    try {
      const buildMethod = Builder.build.overload();
      buildMethod.implementation = function () {
        if (proxyMethod !== null) {
          proxyMethod.call(this, null);
        }
        if (proxySelectorMethod !== null) {
          proxySelectorMethod.call(this, forcedSelector);
        }
        return buildMethod.call(this);
      };
    } catch (error) {
      log(builderClassName + '.build hook skipped: ' + error);
    }

    return true;
  }

  function hookLegacyOkHttp2() {
    let Client;
    try {
      Client = Java.use('com.squareup.okhttp.OkHttpClient');
    } catch (_) {
      return false;
    }

    log('hooking com.squareup.okhttp.OkHttpClient');

    let setProxyMethod = null;
    let setProxySelectorMethod = null;

    function applySelector(client) {
      if (setProxyMethod !== null) {
        setProxyMethod.call(client, null);
      }
      if (setProxySelectorMethod !== null) {
        setProxySelectorMethod.call(client, forcedSelector);
      }
    }

    try {
      setProxyMethod = Client.setProxy.overload('java.net.Proxy');
      setProxyMethod.implementation = function (_proxy) {
        log('OkHttp 2 setProxy(...) intercepted; using ProxySelector');
        const result = setProxyMethod.call(this, null);
        applySelector(this);
        return result;
      };
    } catch (error) {
      log('OkHttp 2 setProxy hook skipped: ' + error);
    }

    try {
      setProxySelectorMethod =
        Client.setProxySelector.overload('java.net.ProxySelector');
      setProxySelectorMethod.implementation = function (_selector) {
        log('OkHttp 2 setProxySelector(...) replaced');
        return setProxySelectorMethod.call(this, forcedSelector);
      };
    } catch (error) {
      log('OkHttp 2 setProxySelector hook skipped: ' + error);
    }

    try {
      const init = Client.$init.overload();
      init.implementation = function () {
        const result = init.call(this);
        applySelector(this);
        return result;
      };
    } catch (error) {
      log('OkHttp 2 constructor hook skipped: ' + error);
    }

    return true;
  }

  let hooked = false;
  OKHTTP3_BUILDER_CLASSES.forEach(function (className) {
    hooked = hookOkHttp3Builder(className) || hooked;
  });
  hooked = hookLegacyOkHttp2() || hooked;

  if (!hooked) {
    log('no OkHttp classes found yet; attach earlier or add shaded class names');
  }

  log('ready: proxy=' + CONFIG.PROXY_TYPE + ' ' +
    CONFIG.PROXY_HOST + ':' + CONFIG.PROXY_PORT);
});
