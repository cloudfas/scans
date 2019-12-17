var assert = require('assert');
var expect = require('chai').expect;
var elbLoggingEnabled = require('./elbLoggingEnabled')

const createCache = (elbData, elbv2Data) => {
    return {
        "elb": {
            "describeLoadBalancers": {
                "us-east-1": {
                    "data": [{
                            "DNSName": "test1",
                        }]
                    }
                },
                "describeLoadBalancerAttributes": {
                    "us-east-1": {
                    "test1": {
                        "data": elbData
                    }
                }

            },
        },
        "elbv2": {
            "describeLoadBalancers": {
                "us-east-1": {
                    "data": [{
                        "DNSName": "test2",
                    }]
                }
            },
            "describeLoadBalancerAttributes": {
                "us-east-1": {
                    "test2": {
                        "data": elbv2Data 
                    
                    }
                }
            }
        }
    }
};


describe('elbLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if elb and elbv2 AccessLogs are both enabled', function (done) {
            const cache = createCache(
                {
                    "LoadBalancerAttributes": {
                        "AccessLog": {
                            "Enabled": true
                        },
                    }
                },
                {
                    "Attributes": [
                      {
                        "Key": "access_logs.s3.enabled",
                        "Value": "true"
                      },
                    ]
                }
                
            );


            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                done()
            }

            elbLoggingEnabled.run(cache, {}, callback)
        })


    })
    describe('run', function () {
        it('should PASS if only elb AccessLogs permissions are present and are enabled', function (done) {

            const cache = createCache(
                {
                    "LoadBalancerAttributes": {
                        "AccessLog": {
                            "Enabled": true
                        },
                    }
                },
                {}
                
            );

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            }

            elbLoggingEnabled.run(cache, {}, callback)
        })


    })

    describe('run', function () {
        it('should FAIL if either access log enablement is set to false', function (done) {

            const cache = createCache(
                {
                    "LoadBalancerAttributes": {
                        "AccessLog": {
                            "Enabled": true
                        },
                    }
                },
                {
                    "Attributes": [
                      {
                        "Key": "access_logs.s3.enabled",
                        "Value": "false"
                      },
                    ]
                }
                
            );

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(2)

                done()
            }

            elbLoggingEnabled.run(cache, {}, callback)
        })


    })

    describe('run', function () {
        it('should FAIL if no load balancers are available', function (done) {

            const callback = (err, results) => {
                expect(results[0]).to.equal(undefined)
                done()
            }

            elbLoggingEnabled.run({}, {}, callback)
        })


    })
})