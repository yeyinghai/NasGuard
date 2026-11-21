Ext.namespace("SYNO.SDS.NasGuard.Utils");

Ext.apply(SYNO.SDS.NasGuard.Utils, function () {
    return {
        getMainHtml: function () {
            var tok = "";
            try { tok = SYNO.SDS.Session.SynoToken || ""; } catch (e) {}
            return '<iframe src="webman/3rdparty/NasGuard/index.html?_ts=' + new Date().getTime() +
                '&SynoToken=' + encodeURIComponent(tok) +
                '" style="width:100%;height:100%;border:none;margin:0" frameborder="0"></iframe>';
        }
    };
}());

Ext.define("SYNO.SDS.NasGuard.Application", {
    extend: "SYNO.SDS.AppInstance",
    appWindowName: "SYNO.SDS.NasGuard.MainWindow",
    constructor: function () {
        this.callParent(arguments);
    }
});

Ext.define("SYNO.SDS.NasGuard.MainWindow", {
    extend: "SYNO.SDS.AppWindow",
    constructor: function (a) {
        var MY = SYNO.SDS.NasGuard;
        this.appInstance = a.appInstance;
        MY.MainWindow.superclass.constructor.call(this, Ext.apply({
            layout: "fit",
            resizable: true,
            maximizable: true,
            minimizable: true,
            width: 1060,
            height: 740,
            html: MY.Utils.getMainHtml()
        }, a));
        MY.Utils.ApplicationWindow = this;
    },
    onOpen: function () {
        SYNO.SDS.NasGuard.MainWindow.superclass.onOpen.apply(this, arguments);
    },
    onRequest: function (a) {
        SYNO.SDS.NasGuard.MainWindow.superclass.onRequest.call(this, a);
    },
    onClose: function () {
        SYNO.SDS.NasGuard.MainWindow.superclass.onClose.apply(this, arguments);
        this.doClose();
        return true;
    }
});
