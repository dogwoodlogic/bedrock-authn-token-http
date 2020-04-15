/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
require('bedrock-mongodb');
require('bedrock-authn-token');
require('bedrock-permission');
require('bedrock-authn-token-http');

require('bedrock-test');
bedrock.start();
