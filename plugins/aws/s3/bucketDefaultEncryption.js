var async = require('async');
var helpers = require('../../../helpers/aws');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'S3 Bucket Default Encryption Enabled',
    category: 'S3',
    description: 'Ensures S3 buckets are configured for Encryption (AES-256 or AWS-KMS). ',
    more_info: '',
    recommended_action: 'Enable Encryption on S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption'],
    compliance: {},

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

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

        //for (i in listBuckets.data) {
            async.each(listBuckets.data, function(bucket, bcb) {
            //var bucket = listBuckets.data[i];
            if (!bucket.Name) return bcb();

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

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
                if(algorithm) {
                    helpers.addResult(results, 0,
                        'Bucket ' + bucket.Name + ' uses ' + algorithm + ' for default Encryption.',
                        'global', bucketResource);
                }
            }
            return bcb()
        });

        callback(null, results, source);
    }
};