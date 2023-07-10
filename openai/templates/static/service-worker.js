self.addEventListener('install', event=>{
    event.waitUntil(caches.open('pandora-cloud-cache').then(function(cache) {
        return cache.addAll(['/apple-touch-icon.png', 
        '/favicon-16x16.png', 
        '/favicon-32x32.png', 
        '/ulp/react-components/1.66.5/css/main.cdn.min.css', 
        '/sweetalert2/bulma.min.css', 
        '/sweetalert2/sweetalert2.all.min-bc15590d.js', 
        '/fonts/colfax/ColfaxAIRegular.woff2', 
        '/fonts/colfax/ColfaxAIRegular.woff', 
        '/fonts/colfax/ColfaxAIRegularItalic.woff2', 
        '/fonts/colfax/ColfaxAIRegularItalic.woff', 
        '/fonts/colfax/ColfaxAIBold.woff2', 
        '/fonts/colfax/ColfaxAIBold.woff', 
        '/fonts/colfax/ColfaxAIBoldItalic.woff2', 
        '/fonts/colfax/ColfaxAIBoldItalic.woff', 
        '/fonts/soehne/soehne-buch-kursiv.woff2', 
        '/fonts/soehne/soehne-buch.woff2', 
        '/fonts/soehne/soehne-halbfett-kursiv.woff2', 
        '/fonts/soehne/soehne-halbfett.woff2', 
        '/fonts/soehne/soehne-kraftig-kursiv.woff2', 
        '/fonts/soehne/soehne-kraftig.woff2', 
        '/fonts/soehne/soehne-mono-buch-kursiv.woff2', 
        '/fonts/soehne/soehne-mono-buch.woff2', 
        '/fonts/soehne/soehne-mono-halbfett.woff2', 
        '/_next/static/chunks/1f110208-cda4026aba1898fb.js', 
        '/_next/static/chunks/012ff928-bcfa62e3ac82441c.js', 
        '/_next/static/chunks/58-87db5ef127e7d0b9.js', 
        '/_next/static/chunks/68a27ff6-a453fd719d5bf767.js', 
        '/_next/static/chunks/68a27ff6-c22fcee210a6c939.js', 
        '/_next/static/chunks/97c719b8-881a2d42a6930388.js', 
        '/_next/static/chunks/293-defd068c38bd0c8d.js', 
        '/_next/static/chunks/386-0a1e4f86c7a1f79c.js', 
        '/_next/static/chunks/496-a3bbd8997fe0f8e4.js', 
        '/_next/static/chunks/709-74a24b5cf35d07f9.js',  
        '/_next/static/chunks/2802bd5f-15923fb46be55b45.js',  
        '/_next/static/chunks/bd26816a-7ae54dd3357d90b4.js',  
        '/_next/static/chunks/index-ba8edbd15bfbb3a1.js', 
        '/_next/static/chunks/polyfills-c67a75d1b6f99dc8.js', 
        '/_next/static/chunks/framework-e23f030857e925d4.js', 
        '/_next/static/chunks/main-35ce5aa6f4f7a906.js', 
        '/_next/static/chunks/webpack-a3f803c49aba2f8d.js', 
        '/_next/static/chunks/pages/_app-12cc5faa218e237a.js', 
        '/_next/static/chunks/pages/_error-433a1bbdb23dd341.js', 
        '/_next/static/chunks/pages/account/cancel-63cd9f049103272b.js', 
        '/_next/static/chunks/pages/account/manage-6ac6d4f0510ced68.js', 
        '/_next/static/chunks/pages/account/upgrade-d6b322741680e2b4.js', 
        '/_next/static/chunks/pages/aip/pluginId/oauth/callback-389963a554a230d2.js', 
        '/_next/static/chunks/pages/auth/error-c7951a77c5f4547f.js', 
        '/_next/static/chunks/pages/auth/ext_callback-927659025ea31258.js', 
        '/_next/static/chunks/pages/auth/ext_callback_refresh-478ebccc4055d75b.js', 
        '/_next/static/chunks/pages/auth/login-f4fdb51b436aaaf4.js', 
        '/_next/static/chunks/pages/auth/logout-47cc26eb7b585e67.js', 
        '/_next/static/chunks/pages/auth/mocked_login-d5fbb97bc5d39e59.js', 
        '/_next/static/chunks/pages/bypass-338530f42d5b2105.js', 
        '/_next/static/chunks/pages/c/[chatId]-92e3c83878b7fde1.js', 
        '/_next/static/chunks/pages/index-ba8edbd15bfbb3a1.js', 
        '/_next/static/chunks/pages/payments/business-e449df976df219cb.js', 
        '/_next/static/chunks/pages/payments/success-66b11e86067b001d.js', 
        '/_next/static/chunks/pages/share/[[...shareParams]]-f2c05a366478888e.js', 
        '/_next/static/chunks/pages/status-6557d60655b68492.js', 
        '/_next/static/css/2ae5d0bc3600f3f7.css', 
        '/_next/static/WLHd8p-1ysAW_5sZZPJIy/_buildManifest.js', 
        '/_next/static/WLHd8p-1ysAW_5sZZPJIy/_ssgManifest.js', ]);
    }));
}
);
self.addEventListener('fetch', function(event) {
    if (event.request.url.startsWith('com.openai.chat://')) {
        event.respondWith(interceptCustomRequest(event.request));
    } else {
        event.respondWith(caches.match(event.request).then(function(response) {
            if (response) {
                return response;
            }
            return fetch(event.request);
        }));
    }
});

async function interceptCustomRequest(request) {
    // 提取请求的前缀
    const prefix = 'com.openai.chat://';
    const url = request.url;
    const path = url.substring(prefix.length);
  
    // 处理自定义请求逻辑
    // ...

    console.log(url);
  
    // 返回自定义的响应对象
    return new Response('Custom Response', { status: 200, headers: { 'Content-Type': 'text/plain' } });
  }
