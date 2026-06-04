/*
 * diagnose-exit.js
 * ------------------------------------------------------------------
 * 诊断脚本：找出到底是“谁”终止了进程（Process terminated）。
 *
 * 用途：
 *   当 App 一启动就 "Process terminated"，先单独跑这个脚本，
 *   它会把所有可能的退出/杀进程入口都挂钩并打印调用栈，
 *   从而判断是不是 App 自带反 Frida / 反调试在主动结束进程。
 *
 * 运行：
 *   frida -U -f <包名> -l diagnose-exit.js
 *
 * 看日志：
 *   - 如果出现 [EXIT] / [KILL] / [native abort] 并带调用栈，
 *     说明是 App（或其安全 SDK）主动结束进程 -> 需要做反检测绕过。
 *   - 如果什么都没打印就直接 terminated，多半是 frida-server 被
 *     检测到、或发生了 native 层 SIGKILL（外部 watchdog），
 *     这种情况通常也指向反调试。
 */

'use strict';

function nativeBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n    ');
    } catch (e) {
        return '(无法获取 native 栈: ' + e + ')';
    }
}

// ----------------- Native 层：libc 退出/信号相关 -----------------
['exit', '_exit', 'abort', 'kill', 'tgkill', 'raise', 'pthread_kill'].forEach(function (sym) {
    var p = Module.findExportByName(null, sym);
    if (p === null) {
        return;
    }
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                console.log('\n[native ' + sym + '] 被调用, arg0=' + args[0] +
                    ' arg1=' + args[1]);
                console.log('  native backtrace:\n    ' + nativeBacktrace(this.context));
            }
        });
        console.log('[diagnose] 已 Hook native: ' + sym);
    } catch (e) {
        console.log('[diagnose] Hook native ' + sym + ' 失败: ' + e);
    }
});

// ----------------- Java 层：各种退出/杀进程 API -----------------
Java.perform(function () {
    function javaStack() {
        try {
            var Log = Java.use('android.util.Log');
            var Throwable = Java.use('java.lang.Throwable');
            return Log.getStackTraceString(Throwable.$new());
        } catch (e) {
            return '(无法获取 java 栈: ' + e + ')';
        }
    }

    function hook(className, methodName, label) {
        try {
            var clazz = Java.use(className);
            if (clazz[methodName] === undefined) {
                return;
            }
            clazz[methodName].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log('\n[' + label + '] ' + className + '.' + methodName +
                        '(' + Array.prototype.join.call(arguments, ', ') + ')');
                    console.log(javaStack());
                    return ov.apply(this, arguments);
                };
            });
            console.log('[diagnose] 已 Hook java: ' + className + '.' + methodName);
        } catch (e) {
            console.log('[diagnose] Hook ' + className + '.' + methodName + ' 失败: ' + e);
        }
    }

    hook('java.lang.System', 'exit', 'EXIT');
    hook('java.lang.Runtime', 'exit', 'EXIT');
    hook('java.lang.Runtime', 'halt', 'EXIT');
    hook('android.os.Process', 'killProcess', 'KILL');
    hook('android.os.Process', 'sendSignal', 'KILL');
    hook('android.os.Process', 'sendSignalQuiet', 'KILL');

    console.log('[diagnose] Java 层退出入口 Hook 完成，等待事件…');
});
