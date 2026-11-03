const assert = require('node:assert/strict')
const test = require('node:test')
const plugin = require('../dist/plugin')

function setup(initialConfig) {
    const allConfigs = { 'proxy-header-auth': initialConfig && { ...initialConfig } }
    const writes = []
    const api = {
        id: 'proxy-header-auth',
        require(name) {
            if (name === './auth') {
                return {
                    getCurrentUsername: ctx => ctx.state.account?.username,
                    setLoggedIn: async (ctx, username) => { ctx.state.account = { username } },
                }
            }
            if (name === './perm') return { accountCanLogin: () => true }
            if (name === './connections') return { normalizeIp: ip => ip }
            throw Error(`Unexpected module: ${name}`)
        },
        misc: { netMatches: () => true },
        getHfsConfig: key => key === 'plugins_config' ? allConfigs : undefined,
        getConfig: key => allConfigs[api.id]?.[key] ?? plugin.config[key]?.defaultValue,
        setConfig(key, value) {
            writes.push(key)
            // HFS removes nullish values and values equal to the field's default
            allConfigs[api.id] = Object.fromEntries(Object.entries({ ...allConfigs[api.id], [key]: value })
                .filter(([key, value]) => value != null && value !== plugin.config[key]?.defaultValue))
        },
        getAccount: username => ({ username }),
        log() {},
    }
    return { api, allConfigs, writes }
}

test('migrates the secret, removes the legacy key and preserves authentication after reload', async () => {
    const { api, allConfigs, writes } = setup({ requiredHeaderName: 'X-Secret', requiredHeaderValue: 'legacy-secret' })
    plugin.init(api)
    assert.deepEqual(allConfigs[api.id], { requiredHeaderName: 'X-Secret', _requiredHeaderValue: 'legacy-secret' })
    const { middleware } = plugin.init(api)
    assert.deepEqual(writes, ['_requiredHeaderValue', 'requiredHeaderValue'])

    for (const [secret, expectedUsername] of [['legacy-secret', 'alice'], ['wrong-secret', undefined], ['', undefined]]) {
        const ctx = {
            path: '/',
            state: {},
            socket: { remoteAddress: '127.0.0.1' },
            get: name => ({ 'X-Secret': secret, 'X-Forwarded-User': 'alice' })[name] || '',
        }
        await middleware(ctx)
        assert.equal(ctx.state.account?.username, expectedUsername)
    }
})

for (const value of ['new-secret', '']) {
    test(`preserves an explicitly configured new value ${JSON.stringify(value)}`, () => {
        const { api, allConfigs, writes } = setup({ requiredHeaderValue: 'legacy-secret', _requiredHeaderValue: value })
        plugin.init(api)
        assert.equal('requiredHeaderValue' in allConfigs[api.id], false)
        assert.equal(api.getConfig('_requiredHeaderValue'), value)
        assert.deepEqual(writes, ['requiredHeaderValue'])
    })
}

test('an empty legacy secret stays empty after migration', () => {
    const { api, allConfigs } = setup({ requiredHeaderValue: '' })
    plugin.init(api)
    assert.equal('requiredHeaderValue' in allConfigs[api.id], false)
    assert.equal(api.getConfig('_requiredHeaderValue'), '')
})

test('leaves fresh installations and already migrated configurations untouched', () => {
    for (const config of [undefined, {}, { _requiredHeaderValue: 'existing-secret' }]) {
        const { api, allConfigs, writes } = setup(config)
        plugin.init(api)
        assert.deepEqual(allConfigs[api.id], config)
        assert.deepEqual(writes, [])
    }
})
