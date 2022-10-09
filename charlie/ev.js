'use strict';

if (Java.available) {

    Java.perform(function() {

        var WebView = Java.use("android.webkit.WebView");

        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            this.loadUrl(url);
            const ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var packagename = context.getPackageName();
            send({
                packageName: packagename,
                method: "loadUrl",
                Url: url,
                Header: "",
                userAgent: this.getSettings().getUserAgentString()
            });
            console.log("WebView.loadUrl url:" + url);
        }

        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, header) {
            this.loadUrl(url, header);
            var keyset = url.keySet();
            var it = keyset.iterator();
            while (it.hasNext()) {
                var keystr = it.next().toString();
                var valuestr = url.get(keystr).toString();
				var s=keystr+valuestr;
                console.log("Header" + keystr + ":" + valuestr)
                send({
                    method: "loadUrlHeader",
                    Url: url,
                    Header:s,
                    userAgent: this.getSettings().getUserAgentString()
                });
            }
           
        }

        WebView.postUrl.overload('java.lang.String', '[B').implementation = function(url, data) {
            console.log("WebView.postUrl :" + url);
            send({
                method: "postUrl",
                Header: "",
                userAgent: this.getSettings().getUserAgentString()
            });
            this.postUrl(url, data);
        }

        WebView.loadDataWithBaseURL.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(url, p2, p3, p4, p5) {
            this.loadDataWithBaseURL(p1, p2, p3, p4, p5);
            send({
                method: "loadDataWithBaseURL",
                Header: "",
                Url: url,
                userAgent: this.getSettings().getUserAgentString()
            });
        };

        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(p0, p1, p2) {
            this.loadUrl(p0, p1, p2);
            console.log("loaddata" + p0 + p1 + p2);
        }

        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onLoadResource.overload('android.webkit.WebView', 'java.lang.String').implementation = function(p0, url) {
            console.log(p0 + url);
            const ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var packagename = context.getPackageName();
            send({
                packageName: packagename,
                method: "onLoadResource",
                Header: "",
                Url: url,
                userAgent: p0.getSettings().getUserAgentString()
            });
            this.onLoadResource(p0, url);

        }




    });

}
