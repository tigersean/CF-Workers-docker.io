// _worker.js

// Docker镜像仓库主机地址
let hub_host = 'registry-1.docker.io';
// Docker认证服务器地址
const auth_url = 'https://auth.docker.io';

let 屏蔽爬虫UA = ['netcraft'];

// 根据主机名选择对应的上游地址
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

/** @type {RequestInit} */
const PREFLIGHT_INIT = {
	headers: new Headers({
		'access-control-allow-origin': '*',
		'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
		'access-control-max-age': '1728000',
	}),
}

function makeRes(body, status = 200, headers = {}) {
	headers['access-control-allow-origin'] = '*'
	return new Response(body, { status, headers })
}

function newUrl(urlStr, base) {
	try {
		return new URL(urlStr, base);
	} catch (err) {
		return null
	}
}

export default {
	async fetch(request, env, ctx) {
		const getReqHeader = (key) => request.headers.get(key);

		let url = new URL(request.url);
		const userAgentHeader = request.headers.get('User-Agent');
		const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
		if (env.UA) 屏蔽爬虫UA = 屏蔽爬虫UA.concat(await ADD(env.UA));
		const workers_url = `https://${url.hostname}`;

		// 获取配置的 Docker Token，并去除可能存在的换行符
		const DOCKER_AUTH_B64 = env.DOCKER_TOKEN_B64 ? env.DOCKER_TOKEN_B64.trim() : "";

		const ns = url.searchParams.get('ns');
		const hostname = url.searchParams.get('hubhost') || url.hostname;
		const hostTop = hostname.split('.')[0];

		let checkHost;
		if (ns) {
			if (ns === 'docker.io') {
				hub_host = 'registry-1.docker.io';
			} else {
				hub_host = ns;
			}
		} else {
			checkHost = routeByHosts(hostTop);
			hub_host = checkHost[0];
		}

		const fakePage = checkHost ? checkHost[1] : false;
		url.hostname = hub_host;
		const hubParams = ['/v1/search', '/v1/repositories'];
		
		if (屏蔽爬虫UA.some(fxxk => userAgent.includes(fxxk)) && 屏蔽爬虫UA.length > 0) {
			return new Response("Blocked", { status: 403 });
		} else if ((userAgent && userAgent.includes('mozilla')) || hubParams.some(param => url.pathname.includes(param))) {
			if (url.pathname == '/') {
                if (env.URL302) return Response.redirect(env.URL302, 302);
                else if (env.URL) return fetch(new Request(env.URL, request));
                else return new Response("Docker Proxy Running", { status: 200 });
			} else {
				if (url.pathname.startsWith('/v1/')) url.hostname = 'index.docker.io';
				else if (fakePage) url.hostname = 'hub.docker.com';
				
                if (url.searchParams.get('q')?.includes('library/') && url.searchParams.get('q') != 'library/') {
					url.searchParams.set('q', url.searchParams.get('q').replace('library/', ''));
				}
				return fetch(new Request(url, request));
			}
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
					'Accept-Encoding': getReqHeader("Accept-Encoding"),
					'Connection': 'keep-alive',
					'Cache-Control': 'max-age=0'
				}
			};
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
			if (v2Match) {
				repo = v2Match[1];
			}
			
			// 如果配置了账号密码，尝试获取 Token
			if (repo && DOCKER_AUTH_B64) {
				const tokenUrl = `${auth_url}/token?service=registry.docker.io&scope=repository:${repo}:pull`;
				const tokenHeaders = {
					'User-Agent': getReqHeader("User-Agent"),
					'Accept': getReqHeader("Accept"),
					'Authorization': `Basic ${DOCKER_AUTH_B64}`
				};

				const tokenRes = await fetch(tokenUrl, { headers: tokenHeaders });
				
				// 【关键修改】如果获取 Token 失败，直接返回错误，不再尝试匿名请求
				if (!tokenRes.ok) {
                    const errText = await tokenRes.text();
                    console.error(`Token fetch failed: ${tokenRes.status} ${errText}`);
					return new Response(`[Auth Error] Failed to get token from Docker Hub. Status: ${tokenRes.status}. Msg: ${errText}`, { 
                        status: tokenRes.status,
                        headers: { 'Content-Type': 'text/plain' }
                    });
				}

				const tokenData = await tokenRes.json();
				const token = tokenData.token;
				
				// 使用获取到的 Token 请求 Registry
				let parameter = {
					headers: {
						'Host': hub_host,
						'User-Agent': getReqHeader("User-Agent"),
						'Accept': getReqHeader("Accept"),
						'Accept-Language': getReqHeader("Accept-Language"),
						'Accept-Encoding': getReqHeader("Accept-Encoding"),
						'Connection': 'keep-alive',
						'Cache-Control': 'max-age=0',
						'Authorization': `Bearer ${token}`
					},
					cacheTtl: 3600
				};
				
				if (request.headers.has("X-Amz-Content-Sha256")) {
					parameter.headers['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
				}

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
		}

		// =========================================================
		// 3. Fallback (没有配置账号，或非 Docker Hub 请求)
		// =========================================================
		let parameter = {
			headers: {
				'Host': hub_host,
				'User-Agent': getReqHeader("User-Agent"),
				'Accept': getReqHeader("Accept"),
				'Accept-Language': getReqHeader("Accept-Language"),
				'Accept-Encoding': getReqHeader("Accept-Encoding"),
				'Connection': 'keep-alive',
				'Cache-Control': 'max-age=0'
			},
			cacheTtl: 3600
		};

		if (request.headers.has("Authorization")) {
			parameter.headers.Authorization = getReqHeader("Authorization");
		}

		if (request.headers.has("X-Amz-Content-Sha256")) {
			parameter.headers['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
		}

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
};

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

async function ADD(envadd) {
	var addtext = envadd.replace(/[	 |"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
	return addtext.split(',');
}
