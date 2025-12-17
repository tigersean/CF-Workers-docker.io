// _worker.js

// Docker镜像仓库主机地址
let hub_host = 'registry-1.docker.io';
// Docker认证服务器地址
const auth_url = 'https://auth.docker.io';

let 屏蔽爬虫UA = ['netcraft'];

function routeByHosts(host) {
	const routes = {
		"quay": "quay.io",
		"gcr": "gcr.io",
		"k8s-gcr": "k8s.gcr.io",
		"k8s": "registry.k8s.io",
		"ghcr": "ghcr.io",
		"cloudsmith": "docker.cloudsmith.io",
		"nvcr": "nvcr.io",
		"test": "registry-1.docker.io",
	};
	if (host in routes) return [routes[host], false];
	else return [hub_host, true];
}

const PREFLIGHT_INIT = {
	headers: new Headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
		'access-control-max-age': '1728000',
	}),
}

function newUrl(urlStr, base) {
	try { return new URL(urlStr, base); } catch (err) { return null }
}

export default {
	async fetch(request, env, ctx) {
		const getReqHeader = (key) => request.headers.get(key);
		let url = new URL(request.url);
		const workers_url = `https://${url.hostname}`;

        // === 调试接口：检查环境变量是否生效 ===
        if (url.pathname === '/auth-debug') {
            const hasToken = !!env.DOCKER_TOKEN_B64;
            const tokenLen = env.DOCKER_TOKEN_B64 ? env.DOCKER_TOKEN_B64.length : 0;
            const tokenSample = env.DOCKER_TOKEN_B64 ? env.DOCKER_TOKEN_B64.substring(0, 4) + "..." : "N/A";
            return new Response(`Environment Variable Check:\nDOCKER_TOKEN_B64 Set: ${hasToken}\nLength: ${tokenLen}\nSample: ${tokenSample}\n\nIf Set is false, please configure it in Cloudflare Dashboard.`, { status: 200 });
        }

		// 获取配置的 Docker Token
		const DOCKER_AUTH_B64 = env.DOCKER_TOKEN_B64 ? env.DOCKER_TOKEN_B64.trim() : "";

		const ns = url.searchParams.get('ns');
		const hostname = url.searchParams.get('hubhost') || url.hostname;
		const hostTop = hostname.split('.')[0];

		let checkHost;
		if (ns) {
			if (ns === 'docker.io') hub_host = 'registry-1.docker.io';
			else hub_host = ns;
		} else {
			checkHost = routeByHosts(hostTop);
			hub_host = checkHost[0];
		}

		const fakePage = checkHost ? checkHost[1] : false;
		url.hostname = hub_host;

        // 首页处理
        if (url.pathname == '/') {
            return new Response("Docker Proxy Running. Set DOCKER_TOKEN_B64 to avoid rate limits.", { status: 200 });
        }

		// 路径修正
		if (url.pathname.startsWith('/v1/')) url.hostname = 'index.docker.io';
		else if (fakePage) url.hostname = 'hub.docker.com';

        if (url.searchParams.get('q')?.includes('library/') && url.searchParams.get('q') != 'library/') {
            url.searchParams.set('q', url.searchParams.get('q').replace('library/', ''));
        }

		if (!/%2F/.test(url.search) && /%3A/.test(url.toString())) {
			let modifiedUrl = url.toString().replace(/%3A(?=.*?&)/, '%3Alibrary%2F');
			url = new URL(modifiedUrl);
		}

		// =========================================================
		// 1. 处理 Token 请求 (auth.docker.io)
		// =========================================================
		if (url.pathname.includes('/token')) {
			let token_parameter = {
				headers: {
					'Host': 'auth.docker.io',
					'User-Agent': getReqHeader("User-Agent"),
					'Accept': getReqHeader("Accept"),
					'Accept-Language': getReqHeader("Accept-Language"),
					'Connection': 'keep-alive',
					'Cache-Control': 'max-age=0'
				}
			};
			// 只有在请求 Token 时才注入 Basic Auth
			if (DOCKER_AUTH_B64) {
				token_parameter.headers['Authorization'] = `Basic ${DOCKER_AUTH_B64}`;
			}
			let token_url = auth_url + url.pathname + url.search;
			return fetch(new Request(token_url, request), token_parameter);
		}

		// 修正 /v2/library 路径
		if (hub_host == 'registry-1.docker.io' && /^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(url.pathname) && !/^\/v2\/library/.test(url.pathname)) {
			url.pathname = '/v2/library/' + url.pathname.split('/v2/')[1];
		}

		// =========================================================
		// 2. 智能获取 Token 并请求镜像
		// =========================================================
		if (
			url.pathname.startsWith('/v2/') &&
			(
				url.pathname.includes('/manifests/') ||
				url.pathname.includes('/blobs/') ||
				url.pathname.includes('/tags/') || 
                url.pathname.endsWith('/tags/list')
			)
		) {
			let repo = '';
			const v2Match = url.pathname.match(/^\/v2\/(.+?)(?:\/(manifests|blobs|tags)\/)/);
			if (v2Match) repo = v2Match[1];
			
			// 如果配置了账号密码，尝试获取 Token
			if (repo && DOCKER_AUTH_B64) {
				const tokenUrl = `${auth_url}/token?service=registry.docker.io&scope=repository:${repo}:pull`;
				const tokenHeaders = {
					'User-Agent': getReqHeader("User-Agent"),
					'Accept': getReqHeader("Accept"),
					'Authorization': `Basic ${DOCKER_AUTH_B64}` // 获取 Token 使用 Basic
				};

				const tokenRes = await fetch(tokenUrl, { headers: tokenHeaders });
				
				if (!tokenRes.ok) {
                    const errText = await tokenRes.text();
					return new Response(`[Auth Error] Failed to get token. Status: ${tokenRes.status}. Msg: ${errText}`, { status: tokenRes.status });
				}

				const tokenData = await tokenRes.json();
				const token = tokenData.token;
				
				// 请求镜像使用 Bearer
				let parameter = {
					headers: {
						'Host': hub_host,
						'User-Agent': getReqHeader("User-Agent"),
						'Accept': getReqHeader("Accept"),
						'Accept-Language': getReqHeader("Accept-Language"),
						'Connection': 'keep-alive',
						'Cache-Control': 'max-age=0',
						'Authorization': `Bearer ${token}` // 注入 Token
					},
					cacheTtl: 3600
				};
				
				if (request.headers.has("X-Amz-Content-Sha256")) {
					parameter.headers['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
				}

				return handleProxy(url, request, parameter, workers_url, hub_host);
			}
		}

		// =========================================================
		// 3. Fallback (无账号配置或非 Docker Hub)
		// =========================================================
		let parameter = {
			headers: {
				'Host': hub_host,
				'User-Agent': getReqHeader("User-Agent"),
				'Accept': getReqHeader("Accept"),
				'Accept-Language': getReqHeader("Accept-Language"),
				'Connection': 'keep-alive',
				'Cache-Control': 'max-age=0'
			},
			cacheTtl: 3600
		};

        // 【重要修复】如果发往 registry-1.docker.io，绝对不要透传客户端的 Authorization (Basic)，否则会报 malformed
        // 除非我们已经有了 Token (上面的逻辑)，否则这里只能匿名请求
        if (hub_host === 'registry-1.docker.io') {
            // 移除 Auth，防止报错
        } else {
            // 其他仓库（如 quay.io）可能支持 Basic，可以透传
            if (request.headers.has("Authorization")) {
                parameter.headers.Authorization = getReqHeader("Authorization");
            }
        }

		if (request.headers.has("X-Amz-Content-Sha256")) {
			parameter.headers['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
		}

		return handleProxy(url, request, parameter, workers_url, hub_host);
	}
};

async function handleProxy(url, request, parameter, workers_url, hub_host) {
    let original_response = await fetch(new Request(url, request), parameter);
    let response_headers = original_response.headers;
    let new_response_headers = new Headers(response_headers);
    let status = original_response.status;

    if (new_response_headers.get("Www-Authenticate")) {
        let auth = new_response_headers.get("Www-Authenticate");
        let re = new RegExp(auth_url, 'g');
        new_response_headers.set("Www-Authenticate", response_headers.get("Www-Authenticate").replace(re, workers_url));
    }

    if (new_response_headers.get("Location")) {
        return httpHandler(request, new_response_headers.get("Location"), hub_host);
    }

    return new Response(original_response.body, {
        status,
        headers: new_response_headers
    });
}

function httpHandler(req, pathname, baseHost) {
	const reqHdrRaw = req.headers;
	if (req.method === 'OPTIONS' && reqHdrRaw.has('access-control-request-headers')) {
		return new Response(null, PREFLIGHT_INIT);
	}
	const reqHdrNew = new Headers(reqHdrRaw);
	reqHdrNew.delete("Authorization"); 
	let urlObj = newUrl(pathname, 'https://' + baseHost);
	const reqInit = {
		method: req.method,
		headers: reqHdrNew,
		redirect: 'follow',
		body: req.body
	};
	return proxy(urlObj, reqInit);
}

async function proxy(urlObj, reqInit) {
	const res = await fetch(urlObj.href, reqInit);
	const resHdrNew = new Headers(res.headers);
	resHdrNew.set('access-control-expose-headers', '*');
	resHdrNew.set('access-control-allow-origin', '*');
	resHdrNew.delete('content-security-policy');
	resHdrNew.delete('content-security-policy-report-only');
	resHdrNew.delete('clear-site-data');
	return new Response(res.body, {
		status: res.status,
		headers: resHdrNew
	});
}
