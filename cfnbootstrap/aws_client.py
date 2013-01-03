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
"""
Base classes for AWS/QUERY clients

Classes:
AWSClient - an HTTP client that makes signed requests

"""
from cfnbootstrap import util
from requests import api
from xml.etree import ElementTree
import StringIO
import base64
import datetime
import hashlib
import hmac
import logging
import operator
import re
import urllib
import urlparse

log = logging.getLogger('cfn.client')

class Signer(object):

    def sign(self, verb, base_url, params, creds, in_headers={}, timestamp=None):
        pass

    def _construct_query(self, sign_data):
        ret_str = ''
        for k, vs in sorted(sign_data.iteritems(), key=operator.itemgetter(0)):
            if isinstance(vs, list):
                for v in sorted(vs):
                    ret_str += '&'.join(urllib.quote(k, safe='~') + '=' + urllib.quote(v, safe='~'))
            else:
                if ret_str:
                    ret_str += '&'
                ret_str += urllib.quote(k, safe='~') + '=' + urllib.quote(vs, safe='~')

        return ret_str

    def _normalize_url(self, base_url):
        return base_url if base_url.endswith('/') else base_url + '/'

class CFNSigner(Signer):

    def sign(self, verb, base_url, params, creds, in_headers={}, timestamp=None):
        base_url = self._normalize_url(base_url)

        if not util.is_ec2():
            raise ValueError("Cannot use CFN signature outside of EC2")

        document = util.get_instance_identity_document()
        signature = util.get_instance_identity_signature()

        new_headers = dict(in_headers)
        new_headers['Authorization'] = 'CFN_V1 %s:%s' % (base64.b64encode(document), signature.replace('\n', ''))

        return (verb, base_url, params, new_headers)

class V2Signer(Signer):

    def sign(self, verb, base_url, in_params, creds, in_headers={}, timestamp=None):
        base_url = self._normalize_url(base_url)

        if not timestamp:
            timestamp = datetime.datetime.utcnow()

        if not in_params:
            'Signature V2 requires at least 1 Query String parameter (Action)'

        params = dict(in_params)
        params['SignatureVersion'] = '2'
        params['SignatureMethod'] = 'HmacSHA256'
        params['AWSAccessKeyId'] = creds.access_key
        params['Timestamp'] = timestamp.replace(microsecond=0).isoformat()
        if creds.security_token:
            params['SecurityToken'] = creds.security_token

        split_url = urlparse.urlsplit(base_url)

        new_headers = dict(in_headers)
        new_headers['Host'] = split_url.netloc
        if verb == 'POST':
            new_headers['Content-type'] = 'application/x-www-form-urlencoded'

        stringToSign = verb + '\n' + split_url.netloc + '\n' + (split_url.path if split_url.path else '/') + '\n'

        stringToSign += self._construct_query(params)

        params['Signature'] = base64.b64encode(hmac.new(creds.secret_key.encode('utf-8'), stringToSign.encode('utf-8'), hashlib.sha256).digest())

        return (verb, base_url, params, new_headers)

class V4Signer(Signer):

    def __init__(self, region, service, terminator='aws4_request'):
        self._region = region
        self._service = service
        self._terminator = terminator

    def sign(self, verb, base_url, params, creds, in_headers={}, timestamp=None):
        base_url = self._normalize_url(base_url)

        if not timestamp:
            timestamp = datetime.datetime.utcnow()

        new_headers = dict(in_headers)

        timestamp_formatted = timestamp.strftime('%Y%m%dT%H%M%SZ')
        timestamp_short = timestamp.strftime('%Y%m%d')

        scope =  timestamp_short + '/' + self._region + '/' + self._service + '/' + self._terminator

        if 'Date' in new_headers:
            del new_headers['Date']
        new_headers['X-Amz-Date'] = timestamp_formatted
        if creds.security_token:
            new_headers['X-Amz-Security-Token'] = creds.security_token
        new_headers['Host'] = urlparse.urlsplit(base_url).netloc
        if verb == 'POST':
            new_headers['Content-type'] = 'application/x-www-form-urlencoded'

        canonical_request = verb + '\n'
        canonical_request += self._canonicalize_uri(base_url) + '\n'
        canonical_request += (self._canonicalize_query(params) if verb == 'GET' else '') + '\n'

        (canonical_headers, signed_headers) = self._canonicalize_headers(new_headers)
        canonical_request += canonical_headers + '\n' + signed_headers + '\n'
        canonical_request += hashlib.sha256(self._construct_query(params).encode('utf-8') if verb == 'POST' else '').hexdigest()

        string_to_sign = 'AWS4-HMAC-SHA256\n' + timestamp_formatted + '\n' + scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        derived_key = hmac.new(("AWS4" + creds.secret_key).encode('utf-8'), timestamp_short.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, self._region.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, self._service.encode('utf-8'), hashlib.sha256).digest()
        derived_key = hmac.new(derived_key, "aws4_request".encode('utf-8'), hashlib.sha256).digest()

        signature = hmac.new(derived_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        credential = creds.access_key + '/' + scope
        new_headers['Authorization'] = 'AWS4-HMAC-SHA256 Credential=%s,SignedHeaders=%s, Signature=%s' % (credential, signed_headers, signature)

        return (verb, base_url, params, new_headers)

    def _canonicalize_uri(self, uri):
        split = urlparse.urlsplit(uri)
        if not split.path:
            return '/'
        path = urlparse.urlsplit(urlparse.urljoin('http://foo.com', split.path.lstrip('/'))).path.rstrip('/')
        return urllib.quote(path, '/~') if path else '/'

    def _canonicalize_query(self, params):
        if not params:
            return ''

        encoded_pairs = ((urllib.quote(entry[0], '~'), urllib.quote(entry[1], '~') if len(entry) > 1 else '') for entry in params.iteritems())
        sorted_pairs = sorted(encoded_pairs, key=operator.itemgetter(0, 1))

        return '&'.join(('='.join(pair) for pair in sorted_pairs))

    def _canonicalize_headers(self, headers):
        canon_headers = {}
        for key, value in ((key.lower(), re.sub(r'(?su)[\s]+', ' ', value).strip()) for key, value in headers.iteritems()):
            if key in canon_headers:
                canon_headers[key] = canon_headers[key] + ',' + value
            else:
                canon_headers[key] = value

        sorted_entries = sorted(canon_headers.iteritems(), key=operator.itemgetter(0))

        return ('\n'.join((':'.join(entry) for entry in sorted_entries)) + '\n', ';'.join((entry[0] for entry in sorted_entries)))


class Credentials(object):
    '''
    AWS Credentials
    '''

    def __init__(self, access_key, secret_key, security_token=None, expiration=None):
        self._access_key = access_key
        self._secret_key = secret_key
        self._security_token = security_token
        self._expiration = expiration

    @property
    def access_key(self):
        return self._access_key

    @property
    def secret_key(self):
        return self._secret_key

    @property
    def security_token(self):
        return self._security_token

    @property
    def expiration(self):
        return self._expiration

    @classmethod
    def from_response(cls, resp):
        body = util.json_from_response(resp)['GetListenerCredentialsResponse']['GetListenerCredentialsResult']['Credentials']
        return Credentials(body['AccessKeyId'],
                           body['SecretAccessKey'],
                           body['SessionToken'],
                           datetime.datetime.utcfromtimestamp(body['Expiration']))



class AwsQueryError(util.RemoteError):

    def __init__(self, status_code, error_code, error_type, msg):
        # Retry for Throttling or InvalidAccessKeyId (IAM propagation delay)
        if status_code == 503 or error_code in ('Throttling', 'InvalidAccessKeyId', 'InvalidClientTokenId'):
            retry_mode = 'RETRIABLE_FOREVER'
        elif error_type == 'Sender':
            retry_mode = 'TERMINAL'
        else:
            retry_mode = 'RETRIABLE'

        super(AwsQueryError, self).__init__(status_code, "%s: %s" % (error_code, msg), retry_mode)

        self.error_code = error_code
        self.error_type = error_type

class Client(object):
    '''
    A base AWS/QUERY client
    '''

    def __init__(self, credentials, is_json, endpoint=None, signer=V2Signer(), xmlns=None):
        self._credentials = credentials
        self._endpoint = endpoint
        self._is_json = is_json
        self._xmlns = xmlns
        self._signer = signer

    @staticmethod
    def _extract_json_message(resp):
        try:
            eDoc = util.json_from_response(resp)['Error']
            code = eDoc['Code']
            message = eDoc['Message']
            error_type = eDoc['Type']

            return AwsQueryError(resp.status_code, code, error_type, message)
        except (TypeError, AttributeError, KeyError, ValueError):
            return AwsQueryError(resp.status_code, 'Unknown', 'Receiver', resp.text)

    @staticmethod
    def _get_xml_extractor(xmlns):
        def _extract_xml_message(resp):
            try:
                eDoc = ElementTree.ElementTree(file=StringIO.StringIO(resp.content))
                code = eDoc.findtext('{%s}Error/{%s}Code' % (xmlns, xmlns))
                error_type = eDoc.findtext('{%s}Error/{%s}Type' % (xmlns, xmlns))
                message = eDoc.findtext('{%s}Error/{%s}Message' % (xmlns, xmlns))

                return AwsQueryError(resp.status_code, code, error_type, message)
            except (TypeError, AttributeError, KeyError, ValueError):
                return AwsQueryError(resp.status_code, 'Unknown', 'Receiver', resp.text)

        return _extract_xml_message

    def _call(self, params, endpoint=None, request_credentials=None, verb='GET'):
        base = endpoint if endpoint else self._endpoint
        creds = request_credentials if request_credentials else self._credentials
        accept_type = "application/json" if self._is_json else "application/xml"
        req = self._signer.sign(verb, base, params, creds, {"Accept" : accept_type})

        return self._make_request(*req)

    def _make_request(self, verb, base_url, params, headers):
        return api.request(verb, base_url,
                           data=params if verb=='POST' else dict(),
                           params=params if verb!='POST' else dict(),
                           headers=headers,
                           verify=util.get_cert(),
                           prefetch=False,
                           config={'danger_mode' : True})
