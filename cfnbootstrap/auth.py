#==============================================================================
# Copyright 2011 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#==============================================================================
from requests.auth import AuthBase, HTTPBasicAuth
import base64
import datetime
import hashlib
import hmac
import logging
import re
import urlparse

log = logging.getLogger("cfn.init")

class S3Signer(object):

    def __init__(self, access_key, secret_key):
        self._access_key = access_key
        self._secret_key = secret_key

    def sign(self, req):
        if 'Date' not in req.headers:
            req.headers['X-Amz-Date'] = datetime.datetime.utcnow().replace(microsecond=0).strftime("%a, %d %b %Y %H:%M:%S GMT")

        stringToSign = req.method + '\n'
        stringToSign += req.headers.get('content-md5', '') + '\n'
        stringToSign += req.headers.get('content-type', '') + '\n'
        stringToSign += req.headers.get('date', '') + '\n'
        stringToSign += self._canonicalize_headers(req)
        stringToSign += self._canonicalize_resource(req)

        signed = base64.encodestring(hmac.new(self._secret_key.encode('utf-8'), stringToSign.encode('utf-8'), hashlib.sha1).digest()).strip()

        req.headers['Authorization'] = 'AWS %s:%s' % (self._access_key, signed)

        return req

    def _canonicalize_headers(self, req):
        headers = [(hdr.lower(), val) for hdr, val in req.headers.iteritems() if hdr.lower().startswith('x-amz')]
        return '\n'.join([hdr + ':' + val for hdr, val in sorted(headers)]) + '\n' if headers else ''

    def _canonicalize_resource(self, req):
        url = urlparse.urlparse(req.full_url)
        match = re.match(r'^([^\.]+)\.s3(-[\w\d-]+)?.amazonaws.com$', url.netloc)
        if match:
            return '/' + match.group(1) + url.path
        return url.path

class S3DefaultAuth(AuthBase):

    def __init__(self):
        self._bucketToSigner = {}

    def add_creds_for_bucket(self, bucket, access_key, secret_key):
        self._bucketToSigner[bucket] = S3Signer(access_key, secret_key)

    def __call__(self, req):
        bucket = self._extract_bucket(req)
        if bucket and bucket in self._bucketToSigner:
            return self._bucketToSigner[bucket].sign(req)
        return req

    def _extract_bucket(self, req):
        url = urlparse.urlparse(req.full_url)
        match = re.match(r'^([^\.]+\.)?s3(-[\w\d-]+)?.amazonaws.com$', url.netloc)
        if not match:
            # Not an S3 URL, skip
            return None
        elif match.group(1):
            # Subdomain-style S3 URL
            return match.group(1).rstrip('.')
        else:
            # This means that we're using path-style buckets
            # lop off the first / and return everything up to the next /
            return url.path[1:].partition('/')[0]

class S3Auth(AuthBase):

    def __init__(self, access_key, secret_key):
        self._signer = S3Signer(access_key, secret_key)

    def __call__(self, req):
        return self._signer.sign(req)

class BasicDefaultAuth(AuthBase):

    def __init__(self):
        self._auths = {}

    def __call__(self, req):
        base_uri = urlparse.urlparse(req.full_url).netloc
        if base_uri in self._auths:
            return self._auths[base_uri](req)
        return req

    def add_password(self, uri, username, password):
        self._auths[uri] = HTTPBasicAuth(username, password)

class DefaultAuth(AuthBase):

    def __init__(self, s3, basic):
        self._s3 = s3
        self._basic = basic

    def __call__(self, req):
        return self._s3(self._basic(req))

class AuthenticationConfig(object):

    def __init__(self, model):

        self._auths = {}

        s3Auth = S3DefaultAuth()
        basicAuth = BasicDefaultAuth()

        for key, config in model.iteritems():
            configType = config.get('type', '')
            if 's3' == configType.lower():
                self._auths[key] = S3Auth(config.get('accessKeyId'), config.get('secretKey'))
                if 'buckets' in config:
                    buckets = [config['buckets']] if isinstance(config['buckets'], basestring) else config['buckets']
                    for bucket in buckets:
                        s3Auth.add_creds_for_bucket(bucket, config.get('accessKeyId'), config.get('secretKey'))
            elif 'basic' == configType.lower():
                self._auths[key] = HTTPBasicAuth(config.get('username'), config.get('password'))
                if 'uris' in config:
                    if isinstance(config['uris'], basestring):
                        basicAuth.add_password(config['uris'], config.get('username'), config.get('password'))
                    else:
                        for u in config['uris']:
                            basicAuth.add_password(u, config.get('username'), config.get('password'))
            else:
                log.warn("Unrecognized authentication type: %s", configType)

        self._defaultAuth = DefaultAuth(s3Auth, basicAuth)

    def get_auth(self, key):
        if not key or not key in self._auths:
            return self._defaultAuth

        return self._auths[key]
