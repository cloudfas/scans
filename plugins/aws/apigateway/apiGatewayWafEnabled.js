var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'API Gateway WAF Enabled',
    category: 'API Gateway',
    description: 'Ensure that all API Gateways have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the API Gateway, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by the region the API Gateway is in. 3. If no Web ACL is found, Create a new Web ACL in the region the Gateway resides and in Resource type to associate with web ACL, select the API Gateway. ',
    apis: ['APIGateway:getRestApis'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var myResourceArns = [];
        console.log(JSON.stringify(cache, null, 2));
        async.each(regions.apigateway, function(loc, lcb){
        });
    }
};