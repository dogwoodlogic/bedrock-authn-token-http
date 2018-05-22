/*
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
const config = require('bedrock').config;
const path = require('path');
require('bedrock-validation');

const cfg = config['authn-token-http'] = {};

cfg.routes = {
  basePath: '/authn/tokens',
  login: '/authn/token/login'
};

// common validation schemas
//config.validation.schema.paths.push(
//  path.join(__dirname, '..', 'schemas'));
