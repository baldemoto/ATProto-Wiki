/* global WIKI */

const _ = require('lodash')
const { Router } = require('express')
const { newClient } = require('../modules/authentication/atproto/authentication')

const router = Router()

router.get('/atproto-login', async (req, res, next) => {
  try {
    const [strategyID, strategy] = (Object.entries(WIKI.auth.strategies).find(s => s[1].isEnabled && s[1].strategyKey === 'atproto') || [])
    if (!strategy) {
      _.set(res.locals, 'pageMeta.title', 'ATProto login not enabled')
      return res.status(404).render('notfound')
    }

    return res.redirect(302, `/login/${strategyID}/callback?${req.url.split('?')[1]}`)
  } catch (err) {
    next(err)
  }
})

router.get('/.well-known/atproto/oauth-client.json', async (req, res, next) => {
  try {
    const strategy = Object.values(WIKI.auth.strategies).find(s => s.isEnabled && s.strategyKey === 'atproto')

    if (!strategy) {
      _.set(res.locals, 'pageMeta.title', 'ATProto login not enabled')
      return res.status(404).render('notfound')
    }

    const client = await newClient({
      host: req.hostname,
      conf: strategy.config
    })

    res.json(client.clientMetadata)
  } catch (error) {
    next(error)
  }
})

module.exports = router
