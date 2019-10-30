var assert = require('assert');
var expect = require('chai').expect;
var elbWafEnabled = require('./elbWafEnabled.js')

const createCache = (loadBalancerData, wafData) => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': loadBalancerData
            }
        },
        wafregional : wafData
    }
}

var nonEmptyWaf = {
    listWebACLs :{
        'us-east-1' : {
            data: [{
                    Name: "WebACLexample",
                    WebACLId: "webacl-1234567891011"
            }]
        }
    },
    listResourcesForWebACL :{
        'us-east-1' : {
            "webacl-1234567891011" :{
                data: {
                    ResourceArns : [
                        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-enabled-load-balancer/50dc6c495c0c9188"
                    ]
                }
            }
        }
    }
}

var errWaf = {
    listWebACLs :{
        'us-east-1' : {
            data: [{
                    Name: "WebACLexample",
                    WebACLId: "webacl-1234567890123"
            }]
        }
    },
    listResourcesForWebACL :{
        'us-east-1' : {
            "webacl-1234567890123" :{
                err: {
                    "message": "The security token included in the request is invalid",
                    "code": "InvalidClientTokenId",
                    "time": "",
                    "requestId": "1234567890",
                    "statusCode": 403,
                    "retryable": false,
                    "retryDelay": 68
                }
            }
        }
    }
}

var emptyWaf = {
    listWebACLs :{
        'us-east-1' : {
            data: []
        }
    },
    listResourcesForWebACL :{
        'us-east-1' : {}
    }
}

var exampleLoadBalancerEnabled ={
    AvailabilityZones: [{
        SubnetId: "subnet-8360a9e7",
        ZoneName: "us-east-1a"
    },{
        SubnetId: "subnet-b7d581c0",
        ZoneName: "us-east-1b"
    }],
    CanonicalHostedZoneId: "Z2P70J7EXAMPLE",
    CreatedTime: "",
    DNSName: "my-load-balancer-424835706.us-east-1.elb.amazonaws.com",
    LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-enabled-load-balancer/50dc6c495c0c9188",
    LoadBalancerName: "my-load-balancer",
    Scheme: "internet-facing",
    SecurityGroups: ["sg-5943793c"],
    State: {
        Code: "active"
    },
    Type: "application",
    VpcId: "vpc-3ac0fb5f"
}

var exampleLoadBalancerNotEnabled = {
    AvailabilityZones: [{
        SubnetId: "subnet-8360a9e7",
        ZoneName: "us-east-1a"
    },{
        SubnetId: "subnet-b7d581c0",
        ZoneName: "us-east-1b"
    }],
    CanonicalHostedZoneId: "Z2P70J7EXAMPLE",
    CreatedTime: "",
    DNSName: "my-load-balancer-424835706.us-east-1.elb.amazonaws.com",
    LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-disabled-load-balancer/50dc6c495c0c9188",
    LoadBalancerName: "my-load-balancer",
    Scheme: "internet-facing",
    SecurityGroups: ["sg-5943793c"],
    State: {
        Code: "active"
    },
    Type: "application",
    VpcId: "vpc-3ac0fb5f"
}

var exampleLoadBalancerError = {
    "err": {
        "message": "The security token included in the request is invalid",
        "code": "InvalidClientTokenId",
        "time": "",
        "requestId": "1234567890",
        "statusCode": 403,
        "retryable": false,
        "retryDelay": 68
    }
}

describe('elbWafEnabled', function () {
    describe('run', function () {
        it('should PASS when all ELB have waf enabled.', function (done) {
            const cache = createCache({data: [exampleLoadBalancerEnabled]}, nonEmptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should FAIL when an ELB does not have waf enabled.', function (done) {
            const cache = createCache({data: [exampleLoadBalancerNotEnabled]}, nonEmptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should PASS when no ELBs are defined', function (done) {
            const cache = createCache({data: []}, nonEmptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0) //overall success since no ELBs found.
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should FAIL when an ELB does not have waf enabled but one does.', function (done) {
            const cache = createCache({data: [exampleLoadBalancerNotEnabled,exampleLoadBalancerEnabled]}, nonEmptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should FAIL when an ELB has an error.', function (done) {
            const cache = createCache({exampleLoadBalancerError}, nonEmptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(3)
                expect(results[1].status).to.equal(0) //overall success since no ELBs found.
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should FAIL when ELB exists with no WAF.', function (done) {
            const cache = createCache({data: [exampleLoadBalancerNotEnabled]}, emptyWaf)

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(2) //overall failed since no WAF found.
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })

        it('should FAIL when an WAF has an error.', function (done) {
            const cache = createCache({data: [exampleLoadBalancerNotEnabled]}, errWaf)

            const callback = (err, results) => {
                console.log(results)
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(3) //due to error returned
                expect(results[1].status).to.equal(2) //overall failed since WAF had error.
                done()
            }

            elbWafEnabled.run(cache, {}, callback)
        })
    })
})
