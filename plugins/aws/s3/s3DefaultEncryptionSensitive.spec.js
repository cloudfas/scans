var assert = require('assert');
var expect = require('chai').expect;
var defaultEncryption = require('./s3DefaultEncryptionSensitive.js')

const createCache = (s3Buckets, encryptionData, taggingData, keyData) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': s3Buckets
            },
            getBucketEncryption: {
                'us-east-1': encryptionData
            },
            getBucketTagging: {
                'us-east-1': taggingData
            }
        },
        kms: {
            describeKey: {
                'us-east-1': keyData
            }
        }
    }
}

const createEncryptionData = (bucketName, data) => {
    returnVal = {}
    returnVal[bucketName] = data
    return returnVal
}

const createTagData = (s3Name, data) => {
    returnVal = {}
    returnVal[s3Name] = data
    return returnVal
}

const createKeyData = (keyId, data) => {
    returnVal = {}
    returnVal[keyId] = data
    return returnVal
}

var exampleBucket = {
    "Name" : "My-First-Bucket",
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
    "ServerSideEncryptionConfiguration": {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }
}

var awsKMSEncryption = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "arn:aws:kms:us-east-1:1234567890:key/abcdefgh-1234-12ab-12ab-012345678910"
            }
        }]
    }
}

var s3Tags = {
    "TagList": [{
        "Key": "SecureKey",
        "Value": "SecureKeyValue"
    }]
}

var s3RandomTags = {
    "TagList": [{
        "Key": "randomKey",
        "Value": "randomKeyValue"
    }]
}

var s3NoTags = {
    "TagList": []
}

var awsKMSKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "AWS"
      }
}

var awsExternalKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "CUSTOMER"
      }
}

describe('bucketDefaultEncryptionSensitive', function () {
    var awsKey = "abcdefgh-1234-12ab-12ab-012345678910"
    var bucketName = "My-First-Bucket"
    describe('run', function () {
        it('should PASS when one bucket has default encryption enabled.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: awsKMSEncryption}),
                createTagData(bucketName, {data: s3Tags}),
                createKeyData(awsKey, {data: awsExternalKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when one bucket has default encryption enabled without CMK.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: aes256Encryption}),
                createTagData(bucketName, {data: s3Tags}),
                createKeyData(awsKey, {data: awsExternalKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should PASS when not tagged.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: aes256Encryption}),
                createTagData(bucketName, {data: s3NoTags}),
                createKeyData(awsKey, {data: awsExternalKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should PASS when tagged with random tags not including special tag.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: aes256Encryption}),
                createTagData(bucketName, {data: s3RandomTags}),
                createKeyData(awsKey, {data: awsExternalKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should PASS when no buckets exist.', function (done) {
            const cache = createCache({data: []}, {}, {}, {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when list buckets errors.', function (done) {
            const cache = createCache({exampleAccessDeniedError}, {}, {}, {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when bucket Encryption Errors.', function (done) {
            const cache = createCache({data: [exampleBucket]}, createEncryptionData(exampleAccessDeniedError), {}, {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when bucket is encrypted but not with CMS.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: awsKMSEncryption}),
                createTagData(bucketName, {data: s3Tags}),
                createKeyData(awsKey, {data: awsKMSKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when tag data errors.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: awsKMSEncryption}),
                createTagData(bucketName, exampleAccessDeniedError),
                createKeyData(awsKey, {data: awsKMSKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should FAIL when KMS describe returns error.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: awsKMSEncryption}),
                createTagData(bucketName, {data: s3Tags}),
                createKeyData(awsKey, exampleAccessDeniedError))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })

        it('should PASS when no settings for sensistive data are passed in.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, {data: awsKMSEncryption}),
                createTagData(bucketName, {data: s3Tags}),
                {})

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
        })

        it('should FAIL when no encryption set on bucket tagged with sensitive data.', function (done) {
            const cache = createCache({data: [exampleBucket]},
                createEncryptionData(bucketName, exampleNoBucketEncryption),
                createTagData(bucketName, {data: s3Tags}),
                createKeyData(awsKey, {data: awsKMSKey}))

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            process.nextTick(() => { defaultEncryption.run(cache, {s3_sensitive_data_tag_key: "SecureKey", s3_sensitive_data_tag_value: "SecureKeyValue"}, callback) })
        })
    })
})