var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB TLS 1.1 or Greater Only',
    category: 'ELB',
    description: 'Ensures ELBs are configured to only accept' +
                 ' connections with TLS 1.1 or greater.',
    more_info: '',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html',
    recommended_action: 'Update all policies to require TLS 1.1 or greater.',
    apis: ['ELB:describeLoadBalancers', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                var elbArn = 'arn:aws:elasticloadbalancing:' +
                              region + ':' + accountId + ':' +
                              'loadbalancer/' + lb.LoadBalancerName;

                // loop through listeners
                var non_tls_listener;
                lb.ListenerDescriptions.forEach(function(listener){
                    // if it is not TLS add protocol and port.
                    if((!listener.PolicyNames.includes("ELBSecurityPolicy-TLS-1-1-2017-01") && !listener.PolicyNames.includes("ELBSecurityPolicy-TLS-1-2-2017-01"))) {
                        non_tls_listener =
                            listener.Listener.Protocol + ' / ' +
                            listener.Listener.LoadBalancerPort
                    }
                });
                if (non_tls_listener){
                    //helpers.addResult(results, 2, non_tls_listener.join(', '), region);
                    msg = "The following listeners are not using TSL 1.1 or above: ";
                    helpers.addResult(
                        results, 2, msg + non_tls_listener, region, elbArn
                    );
                }else{
                    helpers.addResult(results, 0, 'No listeners found', region, elbArn);
                }
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
