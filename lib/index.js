/*
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
const asyncHandler = require('express-async-handler');
const bedrock = require('bedrock');
const {config} = bedrock;
require('bedrock-express');
const brAuthnToken = require('bedrock-authn-token');
const brPassport = require('bedrock-passport');
const {
  ensureAuthenticated,
  optionallyAuthenticated
} = brPassport;
const {BedrockError} = bedrock.util;

// load config defaults
require('./config');

// module API
const api = {};
module.exports = api;

const logger = bedrock.loggers.get('app').child('bedrock-authn-token-http');

// configure passport before serving static files
bedrock.events.on('bedrock-express.configure.static', () => {
  const TokenStrategy = require('./TokenStrategy');
  brPassport.use({
    strategy: new TokenStrategy()
  });
});

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['authn-token-http'];
  const {routes} = cfg;
  const typeRoute = routes.basePath + '/:type';

  // TODO: endpoints
  // create a nonce and email/sms it to user
  // login user via password entry
  // login user via token entry (i.e. user arrived via email or SMS)
  // login user via email link
  // create password
  // delete password
  // get token salt for email/phonenumber/account ID

  // create a token of type `nonce` or `password and notify the user
  app.post(
    typeRoute,
    optionallyAuthenticated,
    // TODO: validate({query: 'services.authn.token.postToken.query'})
    // TODO: validate('services.authn.token.postToken')
    asyncHandler(async (req, res) => {
      const {type} = req.params;
      const {
        account = undefined,
        email = undefined,
        hash = undefined
      } = req.body;

      if(type === 'nonce') {
        // permitted without authentication
        const {actor = null} = (req.user || {});
        await brAuthnToken.set({actor, account, email, type});
        res.status(204).end();
      } else {
        // type must be `password`, authentication required to create
        if(!req.isAuthenticated()) {
          throw new BedrockError(
            'Could not create password; authentication required.',
            'PermissionDenied', {
              public: true,
              httpStatusCode: 400
            });
        }

        const {actor} = req.user;
        await brAuthnToken.set({actor, account, email, type, hash});
        res.status(204).end();
      }

      // notify without blocking
      const {actor = null} = (req.user || {});
      brAuthnToken.notify(
        {actor, account, email, type, notification: {type: 'create'}})
        .catch(err => {
          logger.error('Failed to notify user of token creation.', {
            account,
            email,
            type,
            error: err
          });
        });
    }));

  app.get(
    typeRoute + '/salt',
    // Note: authentication not required for obtaining salt for a user
    //validate({query: 'services.authn.token.getTokensQuery'}),
    asyncHandler(async (req, res) => {
      const {type} = req.params;
      const {account = undefined, email = undefined} = req.query;
      const token = await brAuthnToken.get({actor: null, account, email, type});
      if(!token) {
        return res.status(404).end();
      }
      const {salt} = token;
      res.json({salt});
    }));

  app.delete(
    typeRoute,
    ensureAuthenticated,
    asyncHandler(async (req, res) => {
      const {actor} = req.user;
      const {account} = req.query;
      const {type} = req.params;
      await brAuthnToken.remove({actor, account, type});
      res.status(204).end();
    }));

  app.post(
    routes.login,
    //validate('services.authn.token.postLogin'),
    (req, res, next) => {
      brPassport.authenticate('bedrock-authn-token', (err, user) => {
        if(!user) {
          // user not authenticated
          err = new BedrockError(
            'The email address and password combination is incorrect.',
            'NotAllowedError', {public: true, httpStatusCode: 400});
        }
        if(err) {
          return next(err);
        }
        req.logIn(user, err => {
          if(err) {
            return next(err);
          }
          res.json({account: user.account.id});
        });
      })(req, res, next);
    });
});
