var assert = require('assert');
var expect = require('chai').expect;
var defaultEncryption = require('./s3DefaultEncryption.js')

const createCache = (s3Buckets, encryptionData) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': s3Buckets
            },
            getBucketEncryption: {
                'us-east-1': encryptionData
            }
        }
    }
}

const createEncryptionData = (firstData, secondData) => {
    return {
        "My-First-Bucket" : firstData,
        "My-Second-Bucket" : secondData
    }
}

var exampleFirstBucket = {
    "Name" : "My-First-Bucket",
    "CreationDate" : "2018-02-07T20:51:31.000Z"
}

var exampleSecondBucket = {
    "Name" : "My-Second-Bucket",
    "CreationDate" : "2018-02-07T20:51:31.000Z"
}

var exampleNoBucketEncryption = {
    "err": {
        "message": "The server side encryption configuration was not found",
        "code": "ServerSideEncryptionConfigurationNotFoundError",
        "region": null,
        "time": "2019-10-11T23:10:59.722Z",
        "requestId": "1234567896",
        "extendedRequestId": "1234567896",
        "statusCode": 403,
        "retryable": false,
        "retryDelay": 23.87272591244194
    }
}

var exampleAccessDeniedError = {
    "err": {
        "message": "Access Denied",
        "code": "AccessDenied",
        "region": null,
        "time": "2019-10-11T23:10:59.722Z",
        "requestId": "1234567896",
        "extendedRequestId": "1234567896",
        "statusCode": 403,
        "retryable": false,
        "retryDelay": 23.87272591244194
    }
}

var aes256Encryption = {
    "data": {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }
    }
}

var awsKMSEncryption = {
    "data": {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms"
                }
            }]
        }
    }
}

describe('bucketDefaultEncryption', function () {
    describe('run', function () {
        it('should PASS when one bucket has default encryption enabled - AES256.', function (done) {
            const cache = createCache({data: [exampleFirstBucket]}, createEncryptionData(aes256Encryption,aes256Encryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should PASS when two buckets have default encryption enabled - AES256.', function (done) {
            const cache = createCache({data: [exampleFirstBucket, exampleSecondBucket]}, createEncryptionData(aes256Encryption,aes256Encryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should PASS when one bucket has default encryption enabled - AWS:KMS.', function (done) {
            const cache = createCache({data: [exampleFirstBucket]}, createEncryptionData(awsKMSEncryption,awsKMSEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should PASS when two buckets have default encryption enabled - AWS:KMS.', function (done) {
            const cache = createCache({data: [exampleFirstBucket, exampleSecondBucket]}, createEncryptionData(awsKMSEncryption,awsKMSEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should PASS when two buckets have default encryption enabled - AWS:KMS & AES256.', function (done) {
            const cache = createCache({data: [exampleFirstBucket, exampleSecondBucket]}, createEncryptionData(awsKMSEncryption, aes256Encryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should PASS when no buckets exist.', function (done) {
            const cache = createCache({data: []}, {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should FAIL when list buckets errors.', function (done) {
            const cache = createCache({exampleAccessDeniedError}, {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should FAIL when bucket Encryption Errors.', function (done) {
            const cache = createCache({data: [exampleFirstBucket]}, createEncryptionData(exampleAccessDeniedError,awsKMSEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should FAIL when bucket Contains No Encryption.', function (done) {
            const cache = createCache({data: [exampleFirstBucket]}, createEncryptionData(exampleNoBucketEncryption,awsKMSEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should FAIL when two buckets Contain No Encryption.', function (done) {
            const cache = createCache({data: [exampleFirstBucket, exampleSecondBucket]}, createEncryptionData(exampleNoBucketEncryption,exampleNoBucketEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(2)
                expect(results[1].status).to.equal(2)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should Partial FAIL when one bucket Contains No Encryption but another does - AWS:KMS.', function (done) {
            const cache = createCache({data: [exampleFirstBucket, exampleSecondBucket]}, createEncryptionData(exampleNoBucketEncryption,awsKMSEncryption))

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(2)
                expect(results[1].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })
    })
})