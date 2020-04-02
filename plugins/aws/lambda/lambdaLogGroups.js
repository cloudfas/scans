var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Log Groups',
    category: 'Lambda',
    description: 'Ensures each Lambda function has a valid log group attached to it.',
    more_info: 'Every Lambda function created should automatically have a CloudWatch log group generated to handle its log streams.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html',
    recommended_action: 'Update your functions permissions to allow logging.',
    apis: ['Lambda:listFunctions', 'CloudWatchLogs:describeLogGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            for (f in listFunctions.data) {
                var func = listFunctions.data[f];
                var arn = func.FunctionArn;

                var describeLogGroups = helpers.addSource(cache, source, ['cloudwatchlogs', 'describeLogGroups', region]);

                var result = [0, ''];

                if (!describeLogGroups.data) {
                    result = [3, 'Error querying for log groups'];
                } else if (describeLogGroups.err) {
                    if (describeLogGroups.err.code && policy.err.code == 'ResourceNotFoundException') {
                        result = [0, 'Function does not have a log group attached to it'];
                    } else {
                        result = [3, 'Error querying for log groups: ' + helpers.addError(describeLogGroups)];
                    }
                } else if (describeLogGroups.data) {
                    var found = [];
                    for (n in describeLogGroups.data) {
                        var lg = describeLogGroups.data[n];
                        var lgFunctionName = lg.logGroupName.split("/")[3];

                        if (lgFunctionName && lgFunctionName == func.FunctionName) {
                            found.push(lg.arn);
                        }
                    }

                    if (found.length) {
                        result = [0, 'Function has log groups attached: ' + found.join(', ')];
                    } else {
                        result = [2, 'Function does not have a log group attached to it'];
                    }
                } else {
                    result = [3, 'Unable to obtain log groups for Lambda'];
                }

                helpers.addResult(results, result[0], result[1], region, arn);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};