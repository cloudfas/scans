var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway WAF Enabled',
    category: 'API Gateway',
    description: 'Ensure that all API Gateways have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the API Gateway, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by the region the API Gateway is in. 3. If no Web ACL is found, Create a new Web ACL in the region the Gateway resides and in Resource type to associate with web ACL, select the API Gateway. ',
    apis: ['APIGateway:getRestApis', 'APIGateway:getStages'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.apigateway, function(loc, lcb){

            var restApis = helpers.addSource(cache, source,
                ['apigateway', 'getRestApis', loc]);

            if (!restApis) return lcb();

            if (restApis.err || !restApis.data) {
                helpers.addResult(results, 3, 'Unable to query for API Gateways: ' + helpers.addError(restApis), loc);
                return lcb();
            }

            if (!restApis.data.length) {
                helpers.addResult(results, 0, 'No API Gateways found', loc);
                return lcb();
            }

            async.each(restApis.data, (api, cb) => {

                var stages = helpers.addSource(cache, source, ['apigateway', 'getStages', loc, api.id]);
                if (!stages) {
                    helpers.addResult(results, 3, 'Unable to query for API Stage: ' + helpers.addError(api.name), loc);
                    return cb();
                }

                if (stages.err || !stages.data) {
                    helpers.addResult(results, 3, 'Unable to query for API Stage: ' + helpers.addError(api.name), loc);
                    return cb();
                }

                if (stages.data.item.length < 1) {
                    helpers.addResult(results, 3, 'API Gateway does not have Stages: ' + helpers.addError(api.name), loc);
                    return cb();
                }

                stages.data.item.forEach(stage => {
                    if (!stage.webAclArn || stage.webAclArn.length < 1) {
                        helpers.addResult(results, 2, 'The following API Gateway has a Stage without WAF enabled: ' + api.name);
                    } else {
                        helpers.addResult(results, 0, 'The Stages on ' + api.name + 'have WAF enabled');

                    }
                });

                cb();
            }, function() {
                lcb();
            });
        }, function() {

            callback(null, results, source)
        });
    }
};