var assert = require('assert');
var expect = require('chai').expect;
var elbLoggingEnabled = require('./elbLoggingEnabled')


describe('elbLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if elb and elbv2 AccessLogs are present', function (done) {

            const cache = {
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
                                "data": {
                                    "LoadBalancerAttributes": {
                                        "AccessLog": {
                                            "Enabled": true
                                        },
            
                                    }
                                }
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
                                "data": {
                                    "LoadBalancerAttributes": {                           
                                        "AccessLog": {
                                            "Enabled": false
                                        }, 
                                    }
                                }
                            }
                        } 
                    }
                }
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(2)
                done()
            }

            elbLoggingEnabled.run(cache, {}, callback)
        })


    })

    describe('run', function () {
        it('should PASS if elb AccessLogs permissions are present', function (done) {

            const cache = {
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
                                "data": {
                                    "LoadBalancerAttributes": {                           
                                        "AccessLog": {
                                            "Enabled": false
                                        }, 
                                    }
                                }
                            }
                        } 
                    }
                }
                
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            }

            elbLoggingEnabled.run(cache, {}, callback)
        })


    })

    describe('run', function () {
        it('should PASS if elbv2 AccessLogs permissions are present', function (done) {

            const cache = {
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
                                "data": {
                                    "LoadBalancerAttributes": {
                                        "AccessLog": {
                                            "Enabled": true
                                        },
            
                                    }
                                }
                            }
                        }
                
                    },
                },
                
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
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