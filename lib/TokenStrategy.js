/*
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const LocalStrategy = require('passport-local');
const util = require('util');
const {callbackify} = util;

// export strategy
module.exports = Strategy;

/**
 * Creates a new TokenStrategy for use with passport.
 *
 * @param options the options to pass to the parent LocalStrategy.
 */
function Strategy(options) {
  options = Object.assign({}, options || {});
  if(!('usernameField' in options)) {
    // TODO: support `phoneNumber` in the future
    options.usernameField = 'email';
  }
  if(!('passwordField' in options)) {
    options.passwordField = 'hash';
  }
  options.passReqToCallback = true;

  LocalStrategy.Strategy.call(this, options, callbackify(verify));
  this.name = 'bedrock-authn-token';
}
util.inherits(Strategy, LocalStrategy.Strategy);

async function verify(req, email, hash) {
  const {type} = req.body;
  const account = await brAuthnToken.verify({
    actor: null,
    email,
    type,
    hash
  });
  if(!account) {
    return false;
  }

  const actor = await brAccount.getCapabilities({id: account.id});
  return {account, actor};
}
