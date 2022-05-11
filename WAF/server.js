const express = require('express');
const app = express();

const Waf = require('mini-waf/wafbase');
const wafrules = require('mini-waf/wafrules');

const customSetting = { ...wafrules.DefaultSettings };
customSetting.Rules.push({
  // DoS rule.
  Dacls: [],
  Filters: [
    {
      NetworkLayers:
        Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV4 |
        Waf.WAF_NETWORK_LAYER.PROTOCOL_IPV6,
      MatchTypes: Waf.WAF_MATCH_TYPE.MATCH_ATTEMPTS,
      ManageType: Waf.WAF_MANAGE_TYPE.BLOCK,
      Directions: Waf.WAF_RULE_DIRECTION.INBOUND,

      Attempts: {
        MaxAttempts: 100,
        RenewAttemptsInterval: 1000,
      },

      Description: 'Possible DoS attack.',
    },
  ],
});
app.use(Waf.WafMiddleware(customSetting));

//Create your routes in your way!
app.use((req, res) => {
  //Do your work in anywhere.
  res.send('Some data...');
  res.end();
});

app.get('/dos', (req, res) => {
  res.send({
    time: new Date().valueOf(),
    memory: process.memoryUsage(),
  });
});

app.listen(3000, function () {
  console.log('Running server on port 3000!');
});
