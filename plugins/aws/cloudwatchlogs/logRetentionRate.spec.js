var assert = require('assert');
var expect = require('chai').expect;
var logs = require('./logRetentionRate.js')

const createCache = (groups) => {
    return {
        cloudwatchlogs: {
            describeLogGroups: {
                'us-east-1': {
                    data: groups
                }
            }
        }
    }
};

describe('CloudWatch Log Retention Rate', function () {
    describe('run', function () {
        it('should FAIL if the retention is too low', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 7,
                "arn": "test1",
              }])

            logs.run(cache, {}, callback);
        })

        it('should FAIL if no groups are passed', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(3);
                done()
            };

            const cache = createCache([])

            logs.run(cache, {}, callback);
        })

        it('should PASS if larger than the default setting', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 91,
                "arn": "test1",
              }])

            logs.run(cache, {}, callback);
        })

        it('should PASS if larger than the passed setting', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 7,
                "arn": "test1",
              }])

            logs.run(cache, {log_retention_in_days: 3}, callback);
        })

        
    })
})