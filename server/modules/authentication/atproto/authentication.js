/* global WIKI */

// ------------------------------------
// Auth0 Account
// ------------------------------------

const request = require('request-promise')
const CustomStrategy = require('passport-custom').Strategy
const { JoseKey } = require('@atproto/jwk-jose')
const ATProto = require('@atproto/oauth-client-node')

const states = new Map()
const sessions = new Map()

async function newClient({ host, conf }) {
  const jwk = JSON.parse(conf.privateJWK)
  jwk.kid = jwk.kid || 'default'
  const key = await JoseKey.fromJWK(JSON.stringify(jwk))

  return new ATProto.NodeOAuthClient({
    clientMetadata: {
      'application_type': 'web',
      'redirect_uris': [
        `https://${host}/atproto-login`
      ],
      'response_types': [
        'code'
      ],
      'grant_types': [
        'authorization_code',
        'refresh_token'
      ],
      'scope': conf.scope,
      'token_endpoint_auth_method': 'private_key_jwt',
      'token_endpoint_auth_signing_alg': 'ES256',
      'jwks': {
        keys: [{ ...key.publicJwk, kid: jwk.kid }]
      },
      'dpop_bound_access_tokens': true,
      'client_uri': `https://${host}`,
      'client_id': `https://${host}/.well-known/atproto/oauth-client.json`,
      'client_name': host
    },
    keyset: [key],

    stateStore: {
      set(key, internalState) {
        states.set(key, internalState)
      },
      get(key) {
        return states.get(key)
      },
      del(key) {
        states.delete(key)
      }
    },

    sessionStore: {
      set(sub, session) {
        sessions.set(sub, session)
      },
      get(sub) {
        return sessions.get(sub)
      },
      del(sub) {
        sessions.delete(sub)
      }
    }
  })
}

module.exports = {
  init(passport, conf) {
    passport.use(conf.key, new CustomStrategy(async function (req, done) {
      try {
        const client = await newClient({
          host: req.hostname,
          conf
        }).catch((e) => {
          console.log(e)
          throw e
        })
        if (req.body.email) {
          const resp = await client.authorize(req.body.email, {
            prompt: 'consent'
          })
          return done(null, {
            atprotoRedirect: resp.href
          })
        }
        const params = new URLSearchParams(req.url.split('?')[1])

        const { session, state } = await client.callback(params)

        // Process successful authentication here
        console.log('authorize() was called with state:', state)

        console.log('User authenticated as:', session.did)

        const url = new URL('https://api.bsky.app/xrpc/app.bsky.actor.getProfile')
        url.searchParams.set('actor', session.did)

        const data = await request({
          method: 'GET',
          uri: url.href,
          json: true
        })

        const user = await WIKI.models.users.processProfile({
          providerKey: req.params.strategy,
          profile: {
            ...data,
            id: data.did,
            displayName: data.handle,
            picture: data.avatar,
            email: data.did.replace(/:/g, '_') + '@atproto.invalid'
          }
        })
        done(null, user)
      } catch (error) {
        done(error, null)
      }
    }))
  },
  newClient
}
