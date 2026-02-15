exports.version = 0.3
exports.description = "login from trusted reverse-proxy identity headers (proxy-side auth required)"
exports.apiRequired = 12
exports.repo = "rejetto/hfs-proxy-header-auth"

exports.config = {
    userHeader: {
        defaultValue: 'X-Forwarded-User',
        helperText: "Header containing the authenticated identity (username or email)",
        md: 6
    },
    trustedProxies: {
        defaultValue: '127.0.0.1/8, ::1/128',
        helperText: "Only requests from these proxy IPs/netmasks are trusted. Use * to trust any source.",
        md: 6
    },
    requiredHeaderName: {
        defaultValue: '',
        helperText: "Optional shared-secret header name",
        md: 6
    },
    requiredHeaderValue: {
        defaultValue: '',
        inputProps: { type: 'password' },
        md: 6,
        helperText: "Optional shared-secret header value",
    },
    resolveMode: {
        type: 'select',
        defaultValue: 'username',
        options: {
            "Username only": 'username',
            "Username or email": 'username_or_email'
        },
        md: 6
    },
    allowEmailLocalPart: {
        type: 'boolean',
        defaultValue: true,
        helperText: "If identity is an email, try local-part (before @) as username",
        md: 6
    },
    emailFieldPath: {
        defaultValue: 'plugin.email',
        helperText: "Account field path used when resolve mode includes email (example: plugin.email)",
        md: 6
    },
    mapping: {
        multiline: true,
        defaultValue: '',
        helperText: "Optional explicit mappings, one per line: external-identity = hfs-username",
        md: 6
    },
    autoCreateAccounts: {
        type: 'boolean',
        defaultValue: false,
        helperText: "Create missing accounts automatically",
        md: 6
    },
    autoCreateBelongs: {
        type: 'username',
        multiple: true,
        groups: true,
        defaultValue: [],
        helperText: "Groups assigned to newly auto-created accounts",
        md: 6
    },
    logoutWhenHeaderMissing: {
        type: 'boolean',
        defaultValue: false,
        helperText: "Log out session when trusted request has no identity header",
        md: 6
    },
    logoutWhenUnresolved: {
        type: 'boolean',
        defaultValue: false,
        helperText: "Log out session when identity cannot be mapped to an account",
        md: 6
    },
    logoutRedirect: {
        defaultValue: '',
        helperText: "Optional URL for logout redirect (browser requests). For API requests we send x-proxy-header-auth-logout.",
        md: 6
    },
    bypassAdminAndLogin: {
        type: 'boolean',
        defaultValue: true,
        helperText: "Safety guard: skip header auth on login API endpoints.",
        md: 6
    },
    moreLogs: { type: 'boolean', defaultValue: false, md: 6 },
}

exports.configDialog = {
    maxWidth: 'md'
}

exports.init = api => {
    const { setLoggedIn, getCurrentUsername } = api.require('./auth')
    const { accountCanLogin } = api.require('./perm')
    const { netMatches, wantArray } = api.misc
    const pluginId = api.id || 'proxy-header-auth'

    return { middleware }

    async function middleware(ctx) {
        if (mustBypass(ctx) || !isTrustedProxy(ctx) || !isSecretValid(ctx))
            return
        applyApiLogoutHeader(ctx)

        const identity = getHeader(ctx, api.getConfig('userHeader'))
        const targetUsername = identity && await resolveAccountUsername(identity)
        const resolvedAccount = targetUsername && api.getAccount(targetUsername)
        const reason = !identity ? api.getConfig('logoutWhenHeaderMissing') && "missing identity header"
            : !targetUsername ? api.getConfig('logoutWhenUnresolved') && `unresolved identity: ${identity}`
                : (!resolvedAccount || !accountCanLogin(resolvedAccount)) ? api.getConfig('logoutWhenUnresolved') && `target account cannot login: ${targetUsername}`
                    : ''

        if (reason) {
            const current = getCurrentUsername(ctx)
            if (!current)
                return
            await setLoggedIn(ctx, false)
            ctx.state.account = undefined
            delete ctx.state.usernames
            applyLogoutRedirect(ctx)
            debug(`logged out ${current}: ${reason}`)
            return
        }
        if (!targetUsername || targetUsername === getCurrentUsername(ctx))
            return
        await setLoggedIn(ctx, targetUsername)
        debug(`logged in ${targetUsername} from header identity "${identity}"`)
    }

    function applyLogoutRedirect(ctx) {
        const target = String(api.getConfig('logoutRedirect') || '').trim()
        if (!target)
            return
        const apiPrefix = '/~/api/'
        if (ctx.path.startsWith(apiPrefix))
            return ctx.set('x-proxy-header-auth-logout', target)
        if (!['GET', 'HEAD'].includes(ctx.method))
            return
        ctx.status = 302
        ctx.redirect(target)
        ctx.stop?.()
    }

    function mustBypass(ctx) {
        return api.getConfig('bypassAdminAndLogin') && ctx.path.startsWith('/~/api/login')
    }

    function applyApiLogoutHeader(ctx) {
        if (ctx.path !== '/~/api/logout')
            return
        const target = String(api.getConfig('logoutRedirect') || '').trim()
        if (target)
            ctx.set('x-proxy-header-auth-logout', target)
    }

    function isTrustedProxy(ctx) {
        const proxyPeerIp = getProxyPeerIp(ctx)
        if (!proxyPeerIp)
            return false

        const masks = splitList(api.getConfig('trustedProxies'))
        if (!masks.length) {
            api.log("trustedProxies is empty, refusing all requests")
            return false
        }
        return masks.some(mask => netMatches(proxyPeerIp, mask, true))
    }

    function getProxyPeerIp(ctx) {
        return api.require('./connections').normalizeIp(ctx.socket?.remoteAddress || ctx.ip || '')
    }

    function isSecretValid(ctx) {
        const name = String(api.getConfig('requiredHeaderName') || '').trim()
        const expected = String(api.getConfig('requiredHeaderValue') || '')

        if (!name && !expected)
            return true

        if (!name || !expected) {
            api.log("requiredHeaderName/requiredHeaderValue misconfigured, refusing request")
            return false
        }
        return getHeader(ctx, name) === expected
    }

    async function resolveAccountUsername(identityRaw) {
        const identity = String(identityRaw).trim()
        const mapping = parseMapping(api.getConfig('mapping'))
        const mapped = mapping[identity.toLowerCase()]
        return mapped && api.getAccount(mapped)?.username
            || usernameCandidates(identity).map(candidate => api.getAccount(candidate)?.username).find(Boolean)
            || api.getConfig('resolveMode') === 'username_or_email' && findByEmail(identity)
            || (api.getConfig('autoCreateAccounts') ? autoCreate(identity) : '')
    }

    async function autoCreate(identity) {
        const preferred = usernameCandidates(identity)[0]
        const existing = api.getAccount(preferred)
        if (existing)
            return existing.username

        const belongs = wantArray(api.getConfig('autoCreateBelongs')).filter(Boolean)
        const pluginData = { id: pluginId, auth: true, identity }
        if (identity.includes('@'))
            pluginData.email = identity.toLowerCase()

        const created = await api.addAccount(preferred, { belongs, plugin: pluginData })

        if (created)
            api.log(`auto-created account ${created.username} for identity ${identity}`)

        return created?.username || ''
    }

    function usernameCandidates(valueRaw) {
        const value = String(valueRaw || '').trim()
        if (!value)
            return []

        const list = [value]
        if (api.getConfig('allowEmailLocalPart')) {
            const local = toEmailLocalPart(value)
            if (local && !list.includes(local))
                list.push(local)
        }
        return list
    }

    function findByEmail(valueRaw) {
        const value = String(valueRaw || '').trim().toLowerCase()
        if (!value.includes('@'))
            return ''

        const path = String(api.getConfig('emailFieldPath') || 'plugin.email').trim()
        if (!path)
            return ''

        const accounts = api.getHfsConfig('accounts') || {}
        for (const [username, account] of Object.entries(accounts)) {
            const field = getByPath(account, path)
            if (typeof field === 'string' && field.toLowerCase() === value)
                return username
            if (Array.isArray(field) && field.some(x => typeof x === 'string' && x.toLowerCase() === value))
                return username
        }
        return ''
    }

    function splitList(value) {
        return String(value || '')
            .split(/[\s,;]+/)
            .map(x => x.trim())
            .filter(Boolean)
    }

    function parseMapping(source) {
        const out = {}
        for (const lineRaw of String(source || '').split(/\r?\n/)) {
            const line = lineRaw.trim()
            if (!line || line.startsWith('#'))
                continue
            const separator = line.includes('=') ? '=' : line.includes(':') ? ':' : ''
            if (!separator)
                continue
            const [left, right] = line.split(separator, 2).map(x => x.trim())
            if (!left || !right)
                continue
            out[left.toLowerCase()] = right
        }
        return out
    }

    function getByPath(obj, path) {
        let cur = obj
        for (const key of path.split('.')) {
            if (!key)
                return undefined
            cur = cur?.[key]
            if (cur === undefined)
                return undefined
        }
        return cur
    }

    function toEmailLocalPart(value) {
        const i = value.indexOf('@')
        return i > 0 ? value.slice(0, i) : ''
    }

    function getHeader(ctx, nameRaw) {
        const name = String(nameRaw || '').trim()
        return name ? String(ctx.get(name) || '').trim() : ''
    }

    function debug(msg) {
        if (api.getConfig('moreLogs'))
            api.log(msg)
    }
}
