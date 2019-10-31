var assert = require('assert');
var expect = require('chai').expect;
var elbTLSSecure = require('./elbTLSSecure.js')

const createCache = (loadBalancerData) => {

    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': loadBalancerData
            }
        },
        sts: {
            getCallerIdentity: {
                "us-east-1": {
                    data: "12345678910"
                }
            }
        }
    }
}

//Cache data examples are abbreviated
var ELBwithHTTPListener = (policy) => {
    return {
        "LoadBalancerName": "LoadBalancerExample",
        "DNSName": "LoadBalancerExample.us-east-1.elb.amazonaws.com",
        "ListenerDescriptions": [{
            "Listener": {
                "Protocol": "HTTP",
                "LoadBalancerPort": 80,
                "InstanceProtocol": "HTTP",
                "InstancePort": 80
            },
            "PolicyNames": [policy]
        }]
    }
}

var ELBwithHTTPSListener = (policy) => {
    return {
        "LoadBalancerName": "LoadBalancerExample",
        "DNSName": "LoadBalancerExample.us-east-1.elb.amazonaws.com",
        "ListenerDescriptions": [{
            "Listener": {
                "Protocol": "HTTPS",
                "LoadBalancerPort": 443,
                "InstanceProtocol": "HTTP",
                "InstancePort": 80,
                "SSLCertificateId": "arn:aws:acm:us-east-1:12345678910:certificate/1111111-1111-111111-1111111"
            },
            "PolicyNames": [policy]
        }]
    }
}

var ELB11Policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
var ELB12Policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
var ELBNo11Policy = "ELBSecurityPolicy-2016-08"

var ELBwithError = {
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

describe('elbTLSSecure', function () {
    describe('run', function () {
        it('should PASS when all ELBs have TLS 1.1 or above enabled.', function (done) {
            const cache = createCache({data: [ELBwithHTTPSListener(ELB11Policy), ELBwithHTTPSListener(ELB12Policy)]})

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })

        it('should FAIL when an ELB does not any policy enabled.', function (done) {
            const cache = createCache({data: [ELBwithHTTPListener("")]})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })

        it('should PASS when no ELBs are defined', function (done) {
            const cache = createCache({data: []})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })

        it('should FAIL with one ELB having TLS 1.1 policy and another does not.', function (done) {
            const cache = createCache({data: [ELBwithHTTPSListener(ELB11Policy), ELBwithHTTPSListener(ELBNo11Policy)]})

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(2)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })

        it('should FAIL and output with Two insecure ELBS.', function (done) {
            const cache = createCache({data: [ELBwithHTTPListener(""), ELBwithHTTPSListener(ELBNo11Policy)]})

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(2)
                expect(results[1].status).to.equal(2)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })

        it('should FAIL when an ELB has an error.', function (done) {
            const cache = createCache({ELBwithError})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { elbTLSSecure.run(cache, {}, callback) })
        })
    })
})
