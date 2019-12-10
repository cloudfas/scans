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
                                    "ResponseMetadata": {
                                      "RequestId": "f946630f-dee0-4ae6-889e-1e46c58b39b3"
                                    },
                                    "Attributes": [
                                      {
                                        "Key": "access_logs.s3.enabled",
                                        "Value": "true"
                                      },
                                      {
                                        "Key": "access_logs.s3.bucket",
                                        "Value": "somebucket"
                                      },
                                      {
                                        "Key": "access_logs.s3.prefix",
                                        "Value": "someprefix"
                                      },
                                      {
                                        "Key": "idle_timeout.timeout_seconds",
                                        "Value": "60"
                                      },
                                      {
                                        "Key": "deletion_protection.enabled",
                                        "Value": "false"
                                      },
                                      {
                                        "Key": "routing.http2.enabled",
                                        "Value": "true"
                                      },
                                      {
                                        "Key": "routing.http.drop_invalid_header_fields.enabled",
                                        "Value": "false"
                                      }
                                    ]
                                }                            }
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
                                    "ResponseMetadata": {
                                      "RequestId": "f946630f-dee0-4ae6-889e-1e46c58b39b3"
                                    },
                                    "Attributes": [
                                      {
                                        "Key": "access_logs.s3.enabled",
                                        "Value": "true"
                                      },
                                      {
                                        "Key": "access_logs.s3.bucket",
                                        "Value": "somebucket"
                                      },
                                      {
                                        "Key": "access_logs.s3.prefix",
                                        "Value": "someprefix"
                                      },
                                      {
                                        "Key": "idle_timeout.timeout_seconds",
                                        "Value": "60"
                                      },
                                      {
                                        "Key": "deletion_protection.enabled",
                                        "Value": "false"
                                      },
                                      {
                                        "Key": "routing.http2.enabled",
                                        "Value": "true"
                                      },
                                      {
                                        "Key": "routing.http.drop_invalid_header_fields.enabled",
                                        "Value": "false"
                                      }
                                    ]
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