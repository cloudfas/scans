var async = require('async');
var helpers = require('../../../helpers/aws');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'S3 Encryption for Sensitive Data.',
    category: 'S3',
    description: 'Ensures S3 buckets are configured for Encryption with an AWS-KMS using a Customer Managed Key (CMK)',
    more_info: '',
    recommended_action: 'Enable Encryption on S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'S3:getBucketTagging', 'kms:describeKey'],
    compliance: {},
    settings: {
        s3_sensitive_data_tag_key: {
            name: 'S3 Encryption Tag Key for Sensistive Data',
            description: 'Tagged Sensitive Data instances enforces encryption on S3 Buckets with a Customer Managed Key (CMK)',
            regex: '^.*$',
            default: '',
        },
        s3_sensitive_data_tag_value: {
            name: 'S3 Encryption Tag Value for Sensitive Data',
            description: 'Tagged Sensitive Data instances enforces encryption on S3 Buckets with a Customer Managed Key (CMK)',
            regex: '^.*$',
            default: '^.*$'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var tagValueRegex

        if (!settings.s3_sensitive_data_tag_key) {
            helpers.addResult(results, 0, 'Sensitive Data Setting for S3 not configured.');
            return callback(null, results, source);
        }

        var region = helpers.defaultRegion(settings);
        var tagKey = settings.s3_sensitive_data_tag_key
        try {
            tagValueRegex = RegExp(settings.s3_sensitive_data_tag_value || this.settings.s3_sensitive_data_tag_value.default);
        } catch (err) {
            helpers.addResult(results, 3, err.message, 'global', this.settings.s3_sensitive_data_tag_value.name);
        }

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }


        async.each(listBuckets.data, function(bucket, bcb) {
            if (!bucket.Name) return bcb();

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;
            var bucketTags = helpers.addSource(cache, source,
                ['s3', 'getBucketTagging', region, bucket.Name]);

            if (!bucketTags || bucketTags.err) {
                var tagErr = helpers.addError(bucketTags);
                if (tagErr !== 'The TagList does not exist') {
                    helpers.addResult(results, 3, `Error querying instances tags for ${bucket.Name}: ${helpers.addError(bucketTags)}`, 'global', bucketResource);
                }
                return dcb();
            }

            var targetTag = bucketTags.data.TagList.find(({ Key, Value }) => Key === tagKey && tagValueRegex.test(Value));
            if (!targetTag) {
                return bcb(); // the tag is not found
            }

            var getBucketEncryption = helpers.addSource(cache, source,
                ['s3', 'getBucketEncryption', region, bucket.Name]);

            if (!getBucketEncryption || getBucketEncryption.err || !getBucketEncryption.data) {
                if(getBucketEncryption.err && getBucketEncryption.err.message === 'The server side encryption configuration was not found') {
                    helpers.addResult(results, 2,
                        'No default Encryption set for bucket: ' + bucket.Name,
                        'global', bucketResource);
                } else {
                    helpers.addResult(results, 3,
                        'Error querying for bucket Encryption for bucket: ' + bucket.Name +
                        ': ' + helpers.addError(getBucketEncryption),
                        'global', bucketResource);
                }
            } else {
                var algorithm = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
                if(algorithm === 'aws:kms') {
                    keyId = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyId.split("/")[1]
                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                    if (describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, 'Unable to query for S3 bucket key: ' + helpers.addError(describeKey), region);
                        return bcb();
                    }

                    if(describeKey.data.KeyMetadata.KeyManager === "CUSTOMER") {
                        helpers.addResult(results, 0, 'Encryption with Customer Key is enabled for sensitive data via KMS key: ' + (keyId || 'Unknown'), region, bucketResource);
                    } else {
                        helpers.addResult(results, 2, 'Encryption for sensitive data is enabled, but not with a Customer Managed Key', region, bucketResource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Bucket ' + bucket.Name + ' uses ' + algorithm + ' for default Encryption instead of CMK.',
                        'global', bucketResource);

                }
            }
            return bcb();
        })

        callback(null, results, source);
    }
};