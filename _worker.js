// _worker.js
const hub_host = 'registry-1.docker.io';
const auth_url = 'https://auth.docker.io';
const workers_url_default = 'https://proxy.3-tiger.eu.org'; // 备用

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        
        // 1. 调试接口
        if (url.pathname === '/auth-debug') {
             // 检查变量是否存在，不显示具体值
            return new Response(`DOCKER_TOKEN_B64 Status: ${!!env.DOCKER_TOKEN_B64 ? 'Configured' : 'Missing'}`, { status: 200 });
        }

        // 2. 拦截并处理 Token 请求
        // 当 Docker 客户端向 Worker 请求 Token 时，Worker 注入您的凭证
        if (url.pathname.includes('/token')) {
            const tokenUrl = auth_url + url.pathname + url.search;
            const newHeaders = new Headers(request.headers);
            
            // 关键点：注入 Cloudflare 环境变量中的账号密码
            if (env.DOCKER_TOKEN_B64) {
                // 确保去除首尾空格
                const authVal = env.DOCKER_TOKEN_B64.trim();
                newHeaders.set('Authorization', `Basic ${authVal}`);
            }
            
            // 发送给官方 Auth 服务器
            return fetch(new Request(tokenUrl, {
                method: request.method,
                headers: newHeaders,
                redirect: 'follow'
            }));
        }

        // 3. 处理镜像拉取请求 /v2/
        url.hostname = hub_host;
        
        // 路径修正：补全 /library/
        // 例如：/v2/alpine/manifests/... -> /v2/library/alpine/manifests/...
        if (!url.pathname.includes('/library/') && url.pathname.match(/^\/v2\/[^/]+\/[^/]+\/[^/]+$/)) {
             url.pathname = '/v2/library/' + url.pathname.split('/v2/')[1];
        }

        const newRequest = new Request(url, request);
        const response = await fetch(newRequest);
        
        // 4. 修改 Www-Authenticate 响应头 (最关键的一步！)
        // 只有修改这里，Docker 客户端才会把 Token 请求发回给 Worker，而不是直接发给官方
        const newResponseHeaders = new Headers(response.headers);
        if (newResponseHeaders.has("Www-Authenticate")) {
            const authHeader = newResponseHeaders.get("Www-Authenticate");
            const workerDomain = `https://${new URL(request.url).hostname}`;
            // 把官方的 auth 地址替换成 Worker 的地址
            newResponseHeaders.set("Www-Authenticate", authHeader.replace('https://auth.docker.io', workerDomain));
        }

        return new Response(response.body, {
            status: response.status,
            headers: newResponseHeaders
        });
    }
};
