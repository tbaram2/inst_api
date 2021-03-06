# Copyright (c) 2017 https://github.com/ping
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import hmac
import hashlib
import uuid
import json
import re
import time
import random
import urllib
from datetime import datetime
import gzip
from io import BytesIO
import warnings 
from socket import timeout, error as SocketError
from ssl import SSLError
from .compat import (
    compat_urllib_parse, compat_urllib_error,
    compat_urllib_request, compat_urllib_parse_urlparse,
    compat_http_client)
from .errors import (
    ErrorHandler, ClientError,
    ClientLoginRequiredError, ClientCookieExpiredError,
    ClientConnectionError
)

try:  # Python 3:
    # Not a no-op, we're adding this to the namespace so it can be imported.
    ConnectionError = ConnectionError       # pylint: disable=redefined-builtin
except NameError:  # Python 2:
    class ConnectionError(Exception):
        pass

from .constants import Constants
from .http import ClientCookieJar
from .endpoints import (
    AccountsEndpointsMixin, DiscoverEndpointsMixin, FeedEndpointsMixin,
    FriendshipsEndpointsMixin, LiveEndpointsMixin, MediaEndpointsMixin,
    MiscEndpointsMixin, LocationsEndpointsMixin, TagsEndpointsMixin,
    UsersEndpointsMixin, UploadEndpointsMixin, UsertagsEndpointsMixin,
    CollectionsEndpointsMixin, HighlightsEndpointsMixin,
    IGTVEndpointsMixin,
    ClientDeprecationWarning, ClientPendingDeprecationWarning,
    ClientExperimentalWarning
)

import pymysql
import datetime
from datetime import timedelta
from random import randint
import requests

def to_json(python_object):
    if isinstance(python_object, bytes):
        return {'__class__': 'bytes',
                '__value__': codecs.encode(python_object, 'base64').decode()}
    raise TypeError(repr(python_object) + ' is not JSON serializable')


logger = logging.getLogger(__name__)
# Force Client deprecation warnings to always appear
warnings.simplefilter('always', ClientDeprecationWarning)
warnings.simplefilter('always', ClientPendingDeprecationWarning)
warnings.simplefilter('default', ClientExperimentalWarning)


class Client(AccountsEndpointsMixin, DiscoverEndpointsMixin, FeedEndpointsMixin,
             FriendshipsEndpointsMixin, LiveEndpointsMixin, MediaEndpointsMixin,
             MiscEndpointsMixin, LocationsEndpointsMixin, TagsEndpointsMixin,
             UsersEndpointsMixin, UploadEndpointsMixin, UsertagsEndpointsMixin,
             CollectionsEndpointsMixin, HighlightsEndpointsMixin,
             IGTVEndpointsMixin, object):
    """Main API client class for the private app api."""

    API_URL = 'https://i.instagram.com/api/{version!s}/'

    USER_AGENT = Constants.USER_AGENT
    IG_SIG_KEY = Constants.IG_SIG_KEY
    IG_CAPABILITIES = Constants.IG_CAPABILITIES
    SIG_KEY_VERSION = Constants.SIG_KEY_VERSION
    APPLICATION_ID = Constants.APPLICATION_ID


    test_comment = ''


    follower_max = 1000
    following_max = 1000


    
    # If instagram ban you - query return 400 error.
    error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    error_400_to_ban = 5    

    # If instagram ban you - query return 400 error.
    like_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    like_error_400_to_ban = 7

    like_error_400_to_ban_time = 60*60*12


    # If instagram ban you - query return 400 error.
    follow_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    follow_error_400_to_ban = 10
    follow_error_400_to_ban_time = 60*60*1

    # If instagram ban you - query return 400 error.
    unfollow_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    unfollow_error_400_to_ban = 10
    unfollow_error_400_to_ban_time = 60*60*1

    # If instagram ban you - query return 400 error.
    comment_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    comment_error_400_to_ban = 10
    comment_error_400_to_ban_time = 60*60*1


    # If instagram ban you - query return 400 error.
    get_follower_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    get_follower_error_400_to_ban = 10
    get_follower_error_400_to_ban_time = 60*60*3

    # If instagram ban you - query return 400 error.
    get_following_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    get_following_error_400_to_ban = 10
    get_following_error_400_to_ban_time = 60*60*3

    # If instagram ban you - query return 400 error.
    get_recent_error_400 = 0
    # If you have 3 400 error in row - looks like you banned.
    get_recent_error_400_to_ban = 10
    get_recent_error_400_to_ban_time = 60*60*1        
    
    
    # If InstaBot think you are banned - going to sleep.    
    ban_sleep_time = 1 * 60 * 60


    session_save_time = 1 * 60



    response_content = ''

    

    # All counter.
    bot_mode = 0
    like_counter = 0
    follow_counter = 0
    unfollow_counter = 0
    comments_counter = 0
    current_user = 'hajka'
    current_index = 0
    current_id = 'abcds'
    # List of user_id, that bot follow
    bot_follow_list = []
    user_info_list = []
    user_list = []
    ex_user_list = []
    unwanted_username_list = []
    is_checked = False
    is_selebgram = False
    is_fake_account = False
    is_active_user = False
    is_following = False
    is_follower = False
    is_rejected = False
    is_self_checking = False
    is_by_tag = False
    is_follower_number = 0

    self_following = 0
    self_follower = 0

    # Log setting.
    logging.basicConfig(filename="log/"+datetime.datetime.today().strftime("%Y%m%d")+".log", level=logging.INFO)
    log_file_path = 'log/'
    log_file = 0

    # Other.
    user_id = 0
    media_by_tag = 0
    media_on_feed = []
    media_by_user = []
    login_status = False
    by_location = False

    # Running Times
    start_at_h = 0,
    start_at_m = 0,
    end_at_h = 23,
    end_at_m = 59,

    # For new_auto_mod
    next_iteration = {"Like": 0, "Follow": 0, "Unfollow": 0, "Comments": 0}
    iteration_next_like = 0;
    iteration_next_follow = 0;
    iteration_next_unfollow = 0;
    iteration_next_comments = 0;
    iteration_next_session = 0;
    iteration_next_get_follower = 0;
    iteration_next_get_following = 0;
    iteration_next_recent = 0;


    tag_type = ''
    location_name = ''
    

    def __init__(self, mb_id , **kwargs ):
        """

        :param username: Login username
        :param password: Login password
        :param kwargs: See below

        :Keyword Arguments:
            - **auto_patch**: Patch the api objects to match the public API. Default: False
            - **drop_incompat_key**: Remove api object keys that is not in the public API. Default: False
            - **timeout**: Timeout interval in seconds. Default: 15
            - **api_url**: Override the default api url base
            - **cookie**: Saved cookie string from a previous session
            - **settings**: A dict of settings from a previous session
            - **on_login**: Callback after successful login
            - **proxy**: Specify a proxy ex: 'http://127.0.0.1:8888' (ALPHA)
        :return:
        """


        print("?????????????????? ??????")
        self.login_status = 1 

         # mysql??? ???????????? ??????
        self.conn = pymysql.connect(host='huswssd-0604.cafe24.com',user = 'tbaram3',
                       password='ghdbsdl7615', db='tbaram3',charset='utf8')
        # user??? ?????? ??????, password??? ??????
        self.curs = self.conn.cursor() 

        self.conn.query("set character_set_connection=utf8;")
        self.conn.query("set character_set_server=utf8;")
        self.conn.query("set character_set_client=utf8;")
        self.conn.query("set character_set_results=utf8;")
        self.conn.query("set character_set_database=utf8;")

        query = "SQL Sentence"
        self.curs.execute("set names utf8")
        self.mb_id = mb_id

        sql = "select * from g5_member where mb_id = '%s'" %(mb_id)                
        self.curs.execute(sql)

        
        row = self.curs.fetchone()
        if row:
            self.mb_friend_manage = row[41]
            self.mb_end_service = row[42]
            self.mb_start_time = row[43]
            self.mb_end_time = row[44]
            self.mb_likes_limit = row[45]
            self.mb_filter = row[47]
            self.mb_filter_ar = self.mb_filter.split(',')
            self.mb_auto_follow = row[48]
            self.mb_auto_comment = row[49]           

            self.user_login = row[51]
            temp = row[52]
            password_array = temp.split(" ")
            self.user_password = password_array[len(password_array)-1]
            self.mb_type = row[53]
            self.mb_server = row[54]
            self.mb_giver = row[55]
            self.mb_max_tag = row[71]
            self.mb_user_agent = row[82]

            
        self.log_mod = 1
        self.log_file = 0
##        self.logging.basicConfig(filename="log/"+datetime.datetime.today().strftime("%Y%m%d")+".log", level=logging.INFO)
        self.log_file_path = 'log/'
        
        self.username = self.user_login
        self.password = self.user_password
        print("?????????:",self.username)
        print("???  ???:",self.password)
        
        self.auto_patch = kwargs.pop('auto_patch', False)
        self.drop_incompat_keys = kwargs.pop('drop_incompat_keys', False)
        self.api_url = kwargs.pop('api_url', None) or self.API_URL
        self.timeout = kwargs.pop('timeout', 15)
        self.on_login = kwargs.pop('on_login', None)
        self.logger = logger


        print("??????")
        user_settings = kwargs.pop('settings', None) or {}
        self.uuid = (
            kwargs.pop('guid', None) or kwargs.pop('uuid', None) or
            user_settings.get('uuid') or self.generate_uuid(False))
        self.device_id = (
            kwargs.pop('device_id', None) or user_settings.get('device_id') or
            self.generate_deviceid())
        self.session_id = (
            kwargs.pop('session_id', None) or user_settings.get('session_id') or
            self.generate_uuid(False))        
        self.signature_key = (
            kwargs.pop('signature_key', None) or user_settings.get('signature_key') or
            self.IG_SIG_KEY)
        self.key_version = (
            kwargs.pop('key_version', None) or user_settings.get('key_version') or
            self.SIG_KEY_VERSION)
        self.ig_capabilities = (
            kwargs.pop('ig_capabilities', None) or user_settings.get('ig_capabilities') or
            self.IG_CAPABILITIES)
        self.application_id = (
            kwargs.pop('application_id', None) or user_settings.get('application_id') or
            self.APPLICATION_ID)
        print("??????")

        # to maintain backward compat for user_agent kwarg
        custom_ua = kwargs.pop('user_agent', '') or user_settings.get('user_agent')
        if custom_ua:
            self.user_agent = custom_ua
        else:
            self.app_version = (
                kwargs.pop('app_version', None) or user_settings.get('app_version') or
                Constants.APP_VERSION)
            self.android_release = (
                kwargs.pop('android_release', None) or user_settings.get('android_release') or
                Constants.ANDROID_RELEASE)
            self.android_version = int(
                kwargs.pop('android_version', None) or user_settings.get('android_version') or
                Constants.ANDROID_VERSION)
            self.phone_manufacturer = (
                kwargs.pop('phone_manufacturer', None) or user_settings.get('phone_manufacturer') or
                Constants.PHONE_MANUFACTURER)
            self.phone_device = (
                kwargs.pop('phone_device', None) or user_settings.get('phone_device') or
                Constants.PHONE_DEVICE)
            self.phone_model = (
                kwargs.pop('phone_model', None) or user_settings.get('phone_model') or
                Constants.PHONE_MODEL)
            self.phone_dpi = (
                kwargs.pop('phone_dpi', None) or user_settings.get('phone_dpi') or
                Constants.PHONE_DPI)
            self.phone_resolution = (
                kwargs.pop('phone_resolution', None) or user_settings.get('phone_resolution') or
                Constants.PHONE_RESOLUTION)
            self.phone_chipset = (
                kwargs.pop('phone_chipset', None) or user_settings.get('phone_chipset') or
                Constants.PHONE_CHIPSET)
            self.version_code = (
                kwargs.pop('version_code', None) or user_settings.get('version_code') or
                Constants.VERSION_CODE)

        print("??????????????????")
##        print("cookie:",user_settings.get('cookie'))
        cookie_string = kwargs.pop('cookie', None) or user_settings.get('cookie')
##        print("????????? ????????? ")
##        cookie_string = to_json(cookie_string)
        cookie_jar = ClientCookieJar(cookie_string=cookie_string)
##        print("????????? ????????? ")
        if cookie_string and cookie_jar.auth_expires and int(time.time()) >= cookie_jar.auth_expires:
            raise ClientCookieExpiredError('Cookie expired at {0!s}'.format(cookie_jar.auth_expires))
        cookie_handler = compat_urllib_request.HTTPCookieProcessor(cookie_jar)

        proxy_handler = None
##        print("?????????????????? ")
        proxy = kwargs.pop('proxy', None)
        self.proxy = proxy
        if proxy:
            proxy_address = {
            'http': 'http://' + proxy,
            'https': 'http://' + proxy,}
            proxy_handler = compat_urllib_request.ProxyHandler(proxy_address) 
            
            
##            warnings.warn('Proxy support is alpha.', UserWarning)
##            parsed_url = compat_urllib_parse_urlparse(proxy)
##            if parsed_url.netloc and parsed_url.scheme:
##                proxy_address = '{0!s}://tyler:dlrwoWkd@{1!s}'.format(parsed_url.scheme, parsed_url.netloc)
##                proxy_handler = compat_urllib_request.ProxyHandler({'https': proxy_address})
##            else:
##                raise ValueError('Invalid proxy argument: {0!s}'.format(proxy))
        handlers = []
        if proxy_handler:
            handlers.append(proxy_handler)

        # Allow user to override custom ssl context where possible
        custom_ssl_context = kwargs.pop('custom_ssl_context', None)
        try:
            httpshandler = compat_urllib_request.HTTPSHandler(context=custom_ssl_context)
        except TypeError:
            # py version < 2.7.9
            httpshandler = compat_urllib_request.HTTPSHandler()

        handlers.extend([
            compat_urllib_request.HTTPHandler(),
            httpshandler,
            cookie_handler])
        opener = compat_urllib_request.build_opener(*handlers)
        opener.cookie_jar = cookie_jar
        self.opener = opener

        print("????????? ??????")

        # ad_id must be initialised after cookie_jar/opener because
        # it relies on self.authenticated_user_name
        self.ad_id = (
            kwargs.pop('ad_id', None) or user_settings.get('ad_id') or
            self.generate_adid())

        print("??????????????? id ??????")

        

##        print("cookie_string:",cookie_string)
##        print("cookie_jar:",cookie_jar)

        if not cookie_string:   # [TODO] There's probably a better way than to depend on cookie_string
            if not self.username or not self.password:
                print("login_requirede ??????")
                raise ClientLoginRequiredError('login_required', code=400)
            print("????????????")
            self.login()

            print("????????????")

            r = self.username_info(self.user_login)
            

            self.user_id = r['user']['pk']
            sql = "update g5_member set mb_1 = '%s' where mb_id = '%s'" %(self.user_id,self.mb_id)                
            self.curs.execute(sql)
            time.sleep(3)
            
            
        print("???????????? ????????????")
        self.logger.debug('USERAGENT: {0!s}'.format(self.user_agent))

        sql = "update g5_member set mb_last_reboot = now(), mb_last_error_time = null where mb_id = '%s'" %(self.mb_id)              
        self.curs.execute(sql)

        print("??????????????????")
        super(Client, self).__init__()

    @property
    def settings(self):
        """Helper property that extracts the settings that you should cache
        in addition to username and password."""
        return {
            'uuid': self.uuid,
            'device_id': self.device_id,
            'ad_id': self.ad_id,
            'cookie': self.cookie_jar.dump(),
            'created_ts': int(time.time())
        }

    @property
    def user_agent(self):
        """Returns the useragent string that the client is currently using."""
        return Constants.USER_AGENT_FORMAT.format(**{
            'app_version': self.app_version,
            'android_version': self.android_version,
            'android_release': self.android_release,
            'brand': self.phone_manufacturer,
            'device': self.phone_device,
            'model': self.phone_model,
            'dpi': self.phone_dpi,
            'resolution': self.phone_resolution,
            'chipset': self.phone_chipset,
            'version_code': self.version_code})

    @user_agent.setter
    def user_agent(self, value):
        """Override the useragent string with your own"""
        mobj = re.search(Constants.USER_AGENT_EXPRESSION, value)
        if not mobj:
            raise ValueError('User-agent specified does not fit format required: {0!s}'.format(
                Constants.USER_AGENT_EXPRESSION))
        self.app_version = mobj.group('app_version')
        self.android_release = mobj.group('android_release')
        self.android_version = int(mobj.group('android_version'))
        self.phone_manufacturer = mobj.group('manufacturer')
        self.phone_device = mobj.group('device')
        self.phone_model = mobj.group('model')
        self.phone_dpi = mobj.group('dpi')
        self.phone_resolution = mobj.group('resolution')
        self.phone_chipset = mobj.group('chipset')
        self.version_code = mobj.group('version_code')

    @staticmethod
    def generate_useragent(**kwargs):
        """
        Helper method to generate a useragent string based on device parameters

        :param kwargs:
            - **app_version**
            - **android_version**
            - **android_release**
            - **brand**
            - **device**
            - **model**
            - **dpi**
            - **resolution**
            - **chipset**
        :return: A compatible user agent string
        """
        return Constants.USER_AGENT_FORMAT.format(**{
            'app_version': kwargs.pop('app_version', None) or Constants.APP_VERSION,
            'android_version': int(kwargs.pop('android_version', None) or Constants.ANDROID_VERSION),
            'android_release': kwargs.pop('android_release', None) or Constants.ANDROID_RELEASE,
            'brand': kwargs.pop('phone_manufacturer', None) or Constants.PHONE_MANUFACTURER,
            'device': kwargs.pop('phone_device', None) or Constants.PHONE_DEVICE,
            'model': kwargs.pop('phone_model', None) or Constants.PHONE_MODEL,
            'dpi': kwargs.pop('phone_dpi', None) or Constants.PHONE_DPI,
            'resolution': kwargs.pop('phone_resolution', None) or Constants.PHONE_RESOLUTION,
            'chipset': kwargs.pop('phone_chipset', None) or Constants.PHONE_CHIPSET,
            'version_code': kwargs.pop('version_code', None) or Constants.VERSION_CODE})

    @staticmethod
    def validate_useragent(value):
        """
        Helper method to validate a useragent string for format correctness

        :param value:
        :return:
        """
        mobj = re.search(Constants.USER_AGENT_EXPRESSION, value)
        if not mobj:
            raise ValueError(
                'User-agent specified does not fit format required: {0!s}'.format(
                    Constants.USER_AGENT_EXPRESSION))
        parse_params = {
            'app_version': mobj.group('app_version'),
            'android_version': int(mobj.group('android_version')),
            'android_release': mobj.group('android_release'),
            'brand': mobj.group('manufacturer'),
            'device': mobj.group('device'),
            'model': mobj.group('model'),
            'dpi': mobj.group('dpi'),
            'resolution': mobj.group('resolution'),
            'chipset': mobj.group('chipset'),
            'version_code': mobj.group('version_code'),
        }
        return {
            'user_agent': Constants.USER_AGENT_FORMAT.format(**parse_params),
            'parsed_params': parse_params
        }

    def get_cookie_value(self, key, domain=''):
        now = int(time.time())
        eternity = now + 100 * 365 * 24 * 60 * 60   # future date for non-expiring cookies
        if not domain:
            domain = compat_urllib_parse_urlparse(self.API_URL).netloc

        for cookie in sorted(
                self.cookie_jar, key=lambda c: c.expires or eternity, reverse=True):
            # don't return expired cookie
            if cookie.expires and cookie.expires < now:
                continue
            # cookie domain may be i.instagram.com or .instagram.com
            cookie_domain = cookie.domain
            # simple domain matching
            if cookie_domain.startswith('.'):
                cookie_domain = cookie_domain[1:]
            if not domain.endswith(cookie_domain):
                continue

            if cookie.name.lower() == key.lower():
                return cookie.value

        return None

    @property
    def csrftoken(self):
        """The client's current csrf token"""
        return self.get_cookie_value('csrftoken')

    @property
    def token(self):
        """For compatibility. Equivalent to :meth:`csrftoken`"""
        return self.csrftoken

    @property
    def authenticated_user_id(self):
        """The current authenticated user id"""
        return self.get_cookie_value('ds_user_id')

    @property
    def authenticated_user_name(self):
        """The current authenticated user name"""
        return self.get_cookie_value('ds_user')

    @property
    def phone_id(self):
        """Current phone ID. For use in certain functions."""
        return self.generate_uuid(return_hex=False, seed=self.device_id)

    @property
    def timezone_offset(self):
        """Timezone offset in seconds. For use in certain functions."""
        return int(round((datetime.datetime.now() - datetime.datetime.utcnow()).total_seconds()))

    @property
    def rank_token(self):
        if not self.authenticated_user_id:
            return None
        return '{0!s}_{1!s}'.format(self.authenticated_user_id, self.uuid)

    @property
    def authenticated_params(self):
        return {
            '_csrftoken': self.csrftoken,
            '_uuid': self.uuid,
            '_uid': self.authenticated_user_id
        }

    @property
    def cookie_jar(self):
        """The client's cookiejar instance."""
        return self.opener.cookie_jar

    @property
    def default_headers(self):
        return {
            'User-Agent': self.user_agent,
            'Connection': 'close',
            'Accept': '*/*',
            'Accept-Language': 'ko-KR',
            'Accept-Encoding': 'gzip, deflate',
            'X-IG-Capabilities': self.ig_capabilities,
            'X-IG-Connection-Type': 'WIFI',
            'X-IG-Connection-Speed': '{0:d}kbps'.format(random.randint(1000, 5000)),
            'X-IG-App-ID': self.application_id,
            'X-IG-Bandwidth-Speed-KBPS': '-1.000',
            'X-IG-Bandwidth-TotalBytes-B': '0',
            'X-IG-Bandwidth-TotalTime-MS': '0',
            'X-FB-HTTP-Engine': Constants.FB_HTTP_ENGINE,
        }

    @property
    def radio_type(self):
        """For use in certain endpoints"""
        return 'wifi-none'

    def _generate_signature(self, data):
        """
        Generates the signature for a data string

        :param data: content to be signed
        :return:
        """
        return hmac.new(
            self.signature_key.encode('ascii'), data.encode('ascii'),
            digestmod=hashlib.sha256).hexdigest()

    @classmethod
    def generate_uuid(cls, return_hex=False, seed=None):
        """
        Generate uuid

        :param return_hex: Return in hex format
        :param seed: Seed value to generate a consistent uuid
        :return:
        """
        if seed:
            m = hashlib.md5()
            m.update(seed.encode('utf-8'))
            new_uuid = uuid.UUID(m.hexdigest())
        else:
            new_uuid = uuid.uuid1()
        if return_hex:
            return new_uuid.hex
        return str(new_uuid)

    @classmethod
    def generate_deviceid(cls, seed=None):
        """
        Generate an android device ID

        :param seed: Seed value to generate a consistent device ID
        :return:
        """
        return 'android-{0!s}'.format(cls.generate_uuid(True, seed)[:16])

    def generate_adid(self, seed=None):
        """
        Generate an Advertising ID based on the login username since
        the Google Ad ID is a personally identifying but resettable ID.

        :return:
        """
        modified_seed = seed or self.authenticated_user_name or self.username
        if modified_seed:
            # Do some trivial mangling of original seed
            sha2 = hashlib.sha256()
            sha2.update(modified_seed.encode('utf-8'))
            modified_seed = sha2.hexdigest()
        return self.generate_uuid(False, modified_seed)

    @staticmethod
    def _read_response(response):
        """
        Extract the response body from a http response.

        :param response:
        :return:
        """
        if response.info().get('Content-Encoding') == 'gzip':
            buf = BytesIO(response.read())
            res = gzip.GzipFile(fileobj=buf).read().decode('utf8')
        else:
            res = response.read().decode('utf8')
        return res

    def _call_api(self, endpoint, params=None, query=None, return_response=False, unsigned=False, version='v1'):
        """
        Calls the private api.

        :param endpoint: endpoint path that should end with '/', example 'discover/explore/'
        :param params: POST parameters
        :param query: GET url query parameters
        :param return_response: return the response instead of the parsed json object
        :param unsigned: use post params as-is without signing
        :param version: for the versioned api base url. Default 'v1'.
        :return:
        """
        url = '{0}{1}'.format(self.api_url.format(version=version), endpoint)
        if query:
            url += ('?' if '?' not in endpoint else '&') + compat_urllib_parse.urlencode(query)

        headers = self.default_headers
        data = None
        if params or params == '':
            headers['Content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            if params == '':    # force post if empty string
                data = ''.encode('ascii')
            else:
                if not unsigned:
##                    print("params:",params)
                    json_params = json.dumps(params, separators=(',', ':'))
                    hash_sig = self._generate_signature(json_params)
                    post_params = {
                        'ig_sig_key_version': self.key_version,
                        'signed_body': hash_sig + '.' + json_params
                    }
                else:
                    # direct form post
                    post_params = params
                data = compat_urllib_parse.urlencode(post_params).encode('ascii')

##        print("headers:",headers)
        req = compat_urllib_request.Request(url, data, headers=headers)
  
        try:
            self.logger.debug('REQUEST: {0!s} {1!s}'.format(url, req.get_method()))
            self.logger.debug('DATA: {0!s}'.format(data))
            response = self.opener.open(req, timeout=self.timeout)
        except compat_urllib_error.HTTPError as e:
            error_response = self._read_response(e)
            print("call ?????? code:",e.code)
            print("?????? ?????????:",error_response)

            if str(e.code) == '400' or str(e.code) == '403' :
                print("????????????!")
                #print("response:",error_response)

 
                python_dict = json.loads(error_response)
                if 'message' in python_dict:
                    message = python_dict['message']
                    if message == 'login_required':
                        self.write_log("?????? ???????????? ?????? ?????? ?????? ??? ????????? ??????") 
                        settings_file = "session/%s.txt" %(self.mb_id)
                        os.remove(settings_file)
                        quit()
                
  
                print("python_dict:",python_dict['error_type'])
                if python_dict['error_type'] == 'bad_password' or python_dict['error_type'] == 'checkpoint_challenge_required' :
                    if python_dict['error_type'] == 'bad_password' :
                        mb_problem_type = '??????'
                    elif python_dict['error_type'] == 'checkpoint_challenge_required' :
                        
                                           
                        url = python_dict['challenge']['url']
                        s = requests.Session()     
                        r = s.get(url)
                        finder = r.text.find('SubmitPhoneNumberForm')
                        if finder != -1: 
                            print("????????????")
                            mb_problem_type = '????????????'
                        else:
                            print("????????????")
                            mb_problem_type = '400??????'
                        
     
                    sql = "update g5_member set mb_problem_type ='%s',mb_last_error_time = now(),mb_url = '%s' where mb_id = '%s'" %(mb_problem_type,url, self.mb_id)
    ##                sql = "update g5_member set mb_problem_type ='??????',mb_last_error_time = now() where mb_id = '%s' and mb_problem_type is null" %(self.mb_id)              
                    self.curs.execute(sql)
                    sql = "insert into insta_proxy_list_log set mb_id ='%s', action='%s' , ip = '0', write_time = now()" \
                          %(self.mb_id, mb_problem_type)
                    self.curs.execute(sql)


                
            self.logger.debug('RESPONSE: {0:d} {1!s}'.format(e.code, error_response))
            ErrorHandler.process(e, error_response)

        except (SSLError, timeout, SocketError,
                compat_urllib_error.URLError,   # URLError is base of HTTPError
                compat_http_client.HTTPException,
                ConnectionError) as connection_error:
            raise ClientConnectionError('{} {}'.format(
                connection_error.__class__.__name__, str(connection_error)))

        if return_response:
            return response

        response_content = self._read_response(response)
        self.logger.debug('RESPONSE: {0:d} {1!s}'.format(response.code, response_content))
        json_response = json.loads(response_content)

        if json_response.get('message', '') == 'login_required':
            raise ClientLoginRequiredError(
                json_response.get('message'), code=response.code,
                error_response=json.dumps(json_response))

        # not from oembed or an ok response
        if not json_response.get('provider_url') and json_response.get('status', '') != 'ok':
            raise ClientError(
                json_response.get('message', 'Unknown error'), code=response.code,
                error_response=json.dumps(json_response))

        return json_response


    def write_log(self, log_text):
        """ Write log by print() or logger """
##        print("????????????")
        if self.log_mod == 0:
            try:
                now_time = datetime.datetime.now()
                print(now_time.strftime("%d.%m.%Y_%H:%M")  + " " + log_text)
            except UnicodeEncodeError:
                print("Your text has unicode problem!")
        elif self.log_mod == 1:
            now_time = datetime.datetime.now()
            print(now_time.strftime("%d.%m.%Y_%H:%M")  + "["+ self.mb_id +"]" + log_text)
##            print("????????????1")
            # Create log_file if not exist.
            if self.log_file == 0:
##                print("????????????2")
                
                self.log_file = 1
                now_time = datetime.datetime.now()
##                print("???????????????")
                print(now_time.strftime("%Y%m%d_%H:%M")  + " " + log_text)
                self.log_full_path = '%s%s_%s.log' % (self.log_file_path, now_time.strftime("%Y%m"), self.mb_id)
                formatter = logging.Formatter('%(asctime)s - %(name)s '
                                              '- %(message)s')
                self.logger = logging.getLogger(self.user_login)
                self.hdrl = logging.FileHandler(self.log_full_path )
                self.hdrl.setFormatter(formatter)
                self.logger.setLevel(level=logging.INFO)
                self.logger.addHandler(self.hdrl)
            # Log to log file.
            try:
                self.logger.info(log_text)
            except UnicodeEncodeError:
                print("Your text has unicode problem!")



    def start(self,mode=1):
        while 1: #????????????
            
            if(mode == 1): #????????????
                
              
                for q in range(10):

                    version_code = '104766000'
                    new_version_code = int(version_code) + randint(0,890)
                    self.version_code = str(new_version_code)

                    

                    #????????? ?????? ????????? ??????
                    print("????????? ?????????:",self.mb_end_service)
                    if(self.mb_end_service < datetime.datetime.today().strftime("%Y%m%d")):                        
                        print("????????? ????????? ???????????????.")
                        quit()

                    
                    log_string = "[?????? ?????? ????????? ?????? (????????? 30??? 3??? ????????? ????????? 1???, ????????? 1???]"                
                    self.write_log(log_string)

                    #mb_last_check ????????????
                    now = datetime.datetime.now()                
                    sql = "update g5_member set mb_last_check = now() where mb_id = '%s'" %(self.mb_id)
                    self.curs.execute(sql)


                    #????????? ????????? 0??? ????????? 60 ???????????? 60?????? ?????? ????????????
                    sql = "update g5_member set mb_6 = '60' where (mb_6 > 0 && mb_6 < 60)" 
                    self.curs.execute(sql)                    


                    #????????? ?????? ?????? ??????(???????????? ??????????????????)
                    sql = "alter table insta_likes_%s modify likes_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)

                    sql = "alter table insta_unfollowing_%s modify unfollowing_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)

                    sql = "alter table insta_unfollower_%s modify unfollower_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)
                                      
                    
                    
                    #???????????????????????? ?????? ???????????? ??????
                    print("?????? ?????? ?????? ????????????")
                    sql = "select * from g5_member where mb_id = '%s'" %(self.mb_id)                
                    self.curs.execute(sql)
                    row = self.curs.fetchone()
                    if row:
                        self.mb_friend_manage = row[41]
                        self.mb_end_service = row[42]
                        self.mb_start_time = row[43]
                        self.mb_end_time = row[44]
                        self.mb_likes_limit = row[45]
                        self.mb_filter = row[47]
                        self.mb_filter_ar = self.mb_filter.split(',')
                        self.mb_auto_follow = row[48]
                        self.mb_auto_comment = row[49]
                        print('??????')
                        self.mb_type = row[53]
                        self.mb_server = row[54]
                        self.mb_giver = row[55]
                        self.mb_follower_max = row[68]
                        self.mb_max_tag = row[71]
                        self.mb_id_number = row[40]
                        self.mb_problem_type = row[78]
                        print('??? ')
##                        self.mb_user_agent = row[82]

                    #?????? ????????? ?????? ??????????????? ????????????
                    # sql = "select count(1) likes_count from insta_tag_url_%s where run_yn ='Y' and tag <> '?????????' and tag <> '????????????' and update_time > current_date()+0" %(self.mb_id)
                    sql = "select count(1) likes_count from insta_tag_url_%s where run_yn ='Y' and update_time > current_date()+0" %(self.mb_id)                
                    self.curs.execute(sql)
                    row = self.curs.fetchone()
                    likes_count = row[0]

                    follower_flag = int(self.mb_id_number) % 10
                    
                    print("?????????????????? : %s ~ %s" %(self.mb_start_time, self.mb_end_time))

                    self.mb_start_time = int(self.mb_start_time)
                    if self.mb_start_time > 0:
                        self.mb_start_time = self.mb_start_time + randint(0,2)
                    self.write_log("???????????? ?????? ??????:%s"%(self.mb_start_time))                    
                    print("?????????????????????:",self.mb_problem_type)
                    print("??????    ??????:",self.mb_auto_follow)
                    print("?????????  ??????:",self.mb_auto_comment)
                    print("??????????????????:",self.mb_friend_manage)
                    print("?????????  ??????:",self.mb_giver)
                    print("?????? ????????? ??????    :",self.mb_likes_limit)
                    print("????????????(???????????????):",likes_count)
                    self.write_log("????????????????????????:%s"%(likes_count))

                    now = datetime.datetime.now()
                    


##                    #??????????????? ?????? ?????? ????????? ???????????? ???????????????????????? ????????????????????? ????????? ?????? ?????? ??????!!
##                    if now.hour >= int(self.mb_start_time) and now.hour <= int(self.mb_end_time):                           
##                           #??????????????? Y??? ?????? ?????? ???????????? ????????? ??????.
                                 
                        
                    if int(self.mb_likes_limit)>int(likes_count)  and now.hour >= int(self.mb_start_time) and now.hour <= int(self.mb_end_time)   : #?????? ????????? ????????? ?????? ???????????? ??????                    






                        
                        print("??????????????????:",self.mb_friend_manage)
                        if self.mb_friend_manage == 'Y':
                            self.write_log("???????????? ??????") 
                            self.get_url_friend()               
                        for i in range(2):
                            log_string = "%d?????? ???????????? ?????? " % (i)
                            self.write_log(log_string)
                            #????????? ??????
                            self.like_action()
                            #????????? ??? ????????? ????????????
##                            self.get_following()
##                            self.get_follower()
                            
                            for k in range(45):
                                time.sleep(1)
                            time.sleep(randint(1,15))


                        #?????? ????????? ???????????? ???????????? ????????? ????????? ????????? ?????? ?????? ?????????????????? ??????
                        if self.get_last_tag() != '?????????' and self.get_last_tag() != '????????????':                            
                            #???????????? ????????? ?????? ???????????? ??????
                            user_id = self.get_last_user_id()
                            relationship = self.get_user_relationship(user_id)
                            #(??????,??????) ?????? ????????? ????????? ???????????? 
                            if relationship == 1 :
                                print("????????????:",self.mb_auto_follow)
                                if self.mb_auto_follow == 'Y': 
                                    self.write_log("???????????? Y?????? ????????? ????????? ???????????? ")                
                                    self.follow_action(user_id)
                                    time.sleep(randint(1,10))
                                    

                                print("???????????????:",self.mb_auto_comment)
                                if self.mb_auto_comment == 'Y':                                    
                                    self.write_log("????????? ????????? ?????? ")
                                    self.comment_action()
                                    time.sleep(randint(1,10))

                                self.update_last_url_time()  #???????????? ???????????? ???????????? ?????? ????????? ??????????????? 10????????????..

                        
                        
                    else :
                        self.write_log("??????????????? ???????????? ?????? ?????? ???????????? 100?????? ??????")
                        
                        for j in range(100):
                            time.sleep(1)


                    

                    print("????????????(????????? 24?????? ?????? ??????)")
                    time.sleep(randint(1,10))
                    self.write_log("????????????(????????????)") 
                    self.unfollow_action()

                    #??????????????????????????????
                    self.write_log("?????? ????????? ????????????") 
                    self.get_recent_post()
                    time.sleep(randint(1,6))

                    #???????????????????????????
                    time.sleep(randint(1,6))
                    self.auto_upload()
                    

                    #???????????? ??????
                    self.write_log("???????????? ??????") 
                    self.check_repeat()

                    #????????? ??? ????????? ????????????
                    ## if 1 == 1:
                    if follower_flag == 1 or follower_flag == 2 or follower_flag == 3 or follower_flag == 4 or follower_flag == 5 :
                        self.write_log("??????????????? ?????????, ????????? ????????????") 
                        self.get_following()
                        self.get_follower()

                    #????????? ?????? ????????????
                    self.get_like()

                    self.increase_like()


    def check_repeat(self):
        
        """ ???????????? ??????  """
        print("???????????? ??????")
        sql = "select now()-mb_last_check as last_second from g5_member where mb_id='%s'" %(self.mb_id)                
        self.curs.execute(sql)
        row = self.curs.fetchone()
        last_second = row[0]
        print("????????? last_check :%s ??? ???"%(last_second))
        if(last_second < 100):
            print("???????????????????????? ?????? ??????????????? ??????:",last_second)
            quit()    




    def add_time(self, time):
        """ Make some random for next iteration"""
        return time * 0.9 + time * 0.2 * random.random()


    def get_recent_post(self): 
        """ ?????? ???????????? ????????? ??????."""
  
        try:
            if time.time() > self.iteration_next_recent:
                self.iteration_next_recent = time.time() +  self.add_time(3600) + randint(1,600)  #1?????? ?????? ????????? ????????????.
                print("?????? ????????? ???????????? ?????? username???????????? ?????? ???????????? ?????????.")

                #10??? ??????????????? userid??? username??? ????????? ???????????? ?????? ?????????(?????? ????????? ????????? ????????????..)
                print("user_id:",self.mb_id_number)
                r = self.user_info(self.mb_id_number)
                user_name = r['user']['username']
                self.user_login = user_name
                if user_name != False:
                    print("??????????????????:",user_name)
                    sql = "update g5_member set mb_11 = '%s' where mb_id = '%s'" %(user_name,self.mb_id)
                    self.curs.execute(sql)


                            
                

                


                time.sleep(3)

                result = self.user_info(self.mb_id_number)
    ##                result = self.s.get("http://www.instagram.com/%s"%(self.user_login))
    ##            print(result.status_code) 
                if result['status'] ==  'ok':
     
                    id = result['user']['username']
                    following = result['user']['following_count']
                    follower = result['user']['follower_count']
                    article = result['user']['media_count']

                    self.write_log("???????????????:%s" %(follower))
                    self.write_log("???????????????:%s" %(following)) 

                    sql = "insert into insta_stats_%s set follower = '%s', follwing = '%s', stats_day = current_date() + 0, write_time= now() on duplicate key update follower = '%s', follwing = '%s', stats_day = current_date() + 0, write_time = now()"\
                                  %(self.mb_id, follower, following, follower, following)                
                    self.curs.execute(sql)

                    sql = "delete from insta_recent_%s" %(self.mb_id)
                    self.curs.execute(sql) 



                    
                    now = datetime.datetime.now()
             
                    if self.login_status:
                                          

                        r = self.user_feed(self.mb_id_number)
                        recent_json = list(r['items'])

            
                        for i in range(0,len(recent_json)):
                            
                            self.get_recent_error_400 = 0
                            media_id = recent_json[i]['pk']
                            created_time = recent_json[i]['taken_at']
                            images_thumbnail_url = ''


                            if 'image_versions2' in recent_json[i]:
                                images_thumbnail_url = recent_json[i]['image_versions2']['candidates'][0]['url']
                            if 'carousel_media' in recent_json[i]:
                                images_thumbnail_url = recent_json[i]['carousel_media'][0]['image_versions2']['candidates'][0]['url']
                                
                            likes_count = recent_json[i]['like_count']
                            media_link = "https://www.instagram.com/p/"+ recent_json[i]['code']+"/"
                            
                            
                            sql = "insert into insta_recent_%s set created_time = '%s', media_id = '%s',media_type='carousel', media_link ='%s',likes_count='%s',images_thumbnail_url='%s' on duplicate key update videos_low_url=''"\
                                  %(self.mb_id,created_time,media_id,media_link,likes_count,images_thumbnail_url)                
                            self.curs.execute(sql) 
                            
                            if i == 0 and self.mb_giver == 'Y': #?????? ????????? ????????? ????????? ?????????.(????????? Y??? ????????????)
                                sql = "select count(1) as cnt from insta_auto_like where mb_id = '%s' and day = current_date()+0 "\
                                      %(self.mb_id)
                                self.curs.execute(sql)
                                row = self.curs.fetchone()
                                cnt = row[0]
                                print("cnt:",cnt)

                                #????????? ????????? ?????? ?????? ???????????? ??????
                                sql = "select count(1) as exist from insta_auto_like where pic_url = '%s'"\
                                      %(media_link)
                                self.curs.execute(sql)
                                row = self.curs.fetchone()
                                exist = row[0]
                                print("exist:",exist)
                                if cnt == 0 and exist == 0: #?????? ?????? ???????????? ???????????? ????????? ??????(????????? ????????? ????????? ?????? ????????? ??????..
                                    
                                    sql = "insert into insta_auto_like set mb_id = '%s', day = current_date()+0 , pic_url = '%s',write_time=now() "\
                                          %(self.mb_id,media_link)
                                    print("????????? ?????? ?????? : ",media_link)
                                    self.curs.execute(sql)
                                    #??????????????? ???????????? ??????
##                                    url_increase_likes = "http://followerplus.co.kr/insta_increase_likes.php?mb_id=%s&comment=%s&media_id=%s&url=%s"\
##                                                         %(self.mb_id,self.user_id,media_id,media_link)
##                                    print(url_increase_likes)
##                                    #self.s.get(url_increase_likes)
##                                    self.opener.open(url_increase_likes)

                                    

                                    sql = "select mb_id from g5_member where mb_3 >=  current_date()+0 and mb_15 = 'Y' and mb_4 <> '24' order by mb_3 desc "
                                    self.curs.execute(sql)
                                    rows = self.curs.fetchall()
                                    total_cnt = 0

                                    for j in rows:

                                        mbid = j[0]
##                                        print("mbid:",mbid)
                                        sql = "insert into insta_tag_url_%s set tag='?????????', run_yn='N', comment = '%s', etc_tag = '%s', url='%s', likes=0,tag_type='t', write_time=now() on duplicate key update run_yn='N' "\
                                              %(mbid,self.user_id,media_id,media_link)
##                                        print(sql)
                                        self.curs.execute(sql)
                                        total_cnt = total_cnt+1

                                    print(total_cnt)
                                        

                                    
                                    
                                    
                                else:
                                    print("????????? ?????? ????????? ???????????? ??????????????? ??????")
            else:
                print("?????? ?????? ????????? ?????????????????? ????????????(???):",self.iteration_next_recent - time.time() )
                self.write_log("?????? ?????? ????????? ?????????????????? ????????????")
                
        except  Exception as ex:                    

            if self.get_recent_error_400 > self.get_recent_error_400_to_ban:
                self.write_log("?????? ????????? ???????????? ?????? ???????????? ???????????? ??????")
                quit()
            else :
                self.get_recent_error_400 = self.get_recent_error_400+1
                
            self.write_log("?????? ????????? ??????????????? ????????? ")
            print(ex)





    def get_url_friend(self): 
        """ ???????????? ?????? ?????? ???????????? ????????? ?????????. """
        if self.login_status == 1:
            log_string = "%s ????????? ?????? ?????????(??????) ????????? ?????????." % (self.mb_id)                
            self.write_log(log_string)      
            
            try:
                     
                r = self.feed_timeline() 
                self.media_from_friend = list(r['feed_items'])            
                count_edges = len(self.media_from_friend)
                print("???????????? ?????? ?????? :",count_edges)
                if "media_or_ad" in self.media_from_friend[0]: 
                    if "code" in self.media_from_friend[0]['media_or_ad'] and "injected" not in self.media_from_friend[0]['media_or_ad']: 
                        tag          = '????????????'                    
                        url          = "https://www.instagram.com/p/"+self.media_from_friend[0]['media_or_ad']['code']+"/"
                        likes        = self.media_from_friend[0]['media_or_ad']['like_count']
                        thumbnail    = ''
                        comment      = self.media_from_friend[0]['media_or_ad']['user']['pk']                    
                        etc_tag      = self.media_from_friend[0]['media_or_ad']['pk']          
                        tag_type     = 'f'
            ##            location     = self.media_from_friend[0]['media_or_ad']['location']
                        location_id  = ''
                        location_name= ''            
            ##            if location:
            ##                location_id = self.media_from_friend[0]['media_or_ad']['location']['pk']
            ##                location_name = self.media_from_friend[0]['media_or_ad']['location']['name']
                            
                        
                            

                        sql = "insert into insta_tag_url_%s set tag = '%s', run_yn = 'N', url = '%s', likes = '%s', thumbnail = '%s', write_time = now(), tag_type= '%s', etc_tag='%s', location_id = '%s', location_name = '%s', comment='%s' on duplicate key update tag_type ='%s'" \
                              %(self.mb_id,tag,url,likes,thumbnail,tag_type,etc_tag,location_id,location_name,comment,tag_type)                
                        self.curs.execute(sql)
                        if self.curs:
                            print('?????????????????? ????????? ?????? : %s'%(url)) 
                        else:
                            print('????????? url??? db insert ??????',i)


                #????????? ????????? ??????
                if "media_or_ad" in self.media_from_friend[1]:
                    if "code" in self.media_from_friend[1]['media_or_ad'] and "injected" not in self.media_from_friend[1]['media_or_ad']: 
                        tag          = '????????????'                    
                        url          = "https://www.instagram.com/p/"+self.media_from_friend[1]['media_or_ad']['code']+"/"
                        likes        = self.media_from_friend[1]['media_or_ad']['like_count']
                        thumbnail    = ''
                        comment      = self.media_from_friend[1]['media_or_ad']['user']['pk']                    
                        etc_tag      = self.media_from_friend[1]['media_or_ad']['pk']          
                        tag_type     = 'f'
            ##            location     = self.media_from_friend[1]['media_or_ad']['location']
                        location_id  = ''
                        location_name= ''            
            ##            if location:
            ##                location_id = self.media_from_friend[1]['media_or_ad']['location']['pk']
            ##                location_name = self.media_from_friend[1]['media_or_ad']['location']['name']
                            
                        
                            

                        sql = "insert into insta_tag_url_%s set tag = '%s', run_yn = 'N', url = '%s', likes = '%s', thumbnail = '%s', write_time = now(), tag_type= '%s', etc_tag='%s', location_id = '%s', location_name = '%s', comment='%s' on duplicate key update tag_type ='%s'" \
                              %(self.mb_id,tag,url,likes,thumbnail,tag_type,etc_tag,location_id,location_name,comment,tag_type)                
                        self.curs.execute(sql)
                        if self.curs:
                            print('?????????????????? ????????? ?????? : %s'%(url)) 
                        else:
                            print('????????? url??? db insert ??????',i)                     
                    
            except:
                self.write_log("get_url_friend ??????")
                logging.exception("get_url_friend ??????")
        else:
            return 0                    




    def like_action(self):
        next_url = self.get_next_url()
        media_id = self.get_next_media_id()
        if (next_url != 0): #????????? url??? ?????????
            print(next_url)
            # print(media_id)
              
            if time.time() > self.iteration_next_like:   #????????? ?????? ???????????? ?????????
                
                like = self.like(media_id)
                log_string = "(%d) ????????? ????????? ?????? ?????? " \
                                 % (self.like_error_400)

                self.write_log(log_string)
                
                if like == 1:  
                        self.iteration_next_like = 0 #????????? ?????? ???????????? ??????                        
                        self.update_next_url_liked(next_url,'Y') ## run_yn ??? Y??? ??????
                        self.like_error_400 = 0
                        self.like_counter += 1
                        log_string = "Liked: %s. Like #%i. %s" % \
                                     (media_id,
                                      self.like_counter,next_url)                    
                        self.write_log(log_string) 
                        print("like??????: %i ???"%(self.like_counter))

                        sql = "update g5_member set like_check = '0', mb_problem_type = null where mb_id = '%s'" %(self.mb_id)
                        self.curs.execute(sql)                        
                else: 
                    self.update_next_url_liked(next_url,'F') ## run_yn ??? F??? ??????
                    log_string = "(%d)??????????????????: %s.  " \
                                 % (self.like_error_400, next_url)

                    self.write_log(log_string)                    
                    # Some error. If repeated - can be ban!
                    if self.like_error_400 >= self.like_error_400_to_ban: # ????????? 5??? ?????? ????????? ????????? ????????? ?????????
                        print("????????? ?????? ?????? ?????? : ",self.like_error_400)
                        self.write_log("?????? ????????? ?????? ?????????. ?????? ?????? ?????????.")

                        sql = "select like_check from g5_member where mb_id = '%s'" %(self.mb_id)                
                        self.curs.execute(sql)
                        row = self.curs.fetchone()
                        like_check = row[0]
                        if like_check != '1':
                            sql = "update g5_member set like_check = '1' where mb_id = '%s'" %(self.mb_id)
                            self.curs.execute(sql)
                            self.write_log("?????? 5??? ?????? ?????? ?????? ????????????????????? ????????? ???????????? ??????")
                        else:



                            if self.mb_problem_type != '?????????????????????' :
                                sql = "update g5_member set mb_6 = round(mb_6 * 0.5)  where mb_id = '%s'" %(self.mb_id)                
                                self.curs.execute(sql)  #?????? ??????????????? ???????????? ????????? ????????? ???????????? ??????(???????????? ??????????????? ?????????)
  
                                after_count = int(self.mb_likes_limit)*0.5
                 

                                sql = "insert into insta_proxy_list_log set mb_id ='%s', action='???????????????',  memo = '%s(??????)', write_time = now()" \
                                    %(self.mb_id, after_count)                
                                self.curs.execute(sql)

                                
                                self.write_log("????????? ?????? %s??? ?????? ??????!!" %(after_count) )                                

                                   
                                
                                sql = "update g5_member set mb_last_error_time = now(), mb_problem_type ='?????????????????????' where mb_id = '%s'" %(self.mb_id)                
                                self.curs.execute(sql)

                                
                                
                            self.write_log("10??? ?????? ????????? ???????????????????????? ????????? ??????. ???????????? ????????? ??????????????? ????????? ??????")

                            sql = "insert into insta_proxy_list_log set mb_id ='%s', action='???????????????', class = '%s', ip = '%s', memo = '%s', write_time = now(), memo2 = '%s'" \
                                  %(self.mb_id, '', self.proxy, '', '')                
                            self.curs.execute(sql)      
                        quit() 
                    else:
                        self.like_error_400 += 1
                        # self.change_proxy()
     
             
            else:
                print("????????? ?????? ?????????.. ???????????? : ",self.iteration_next_like-time.time())
            
        else: 
            self.get_url_by_tag(self.get_next_tag(),'t')  #????????? ????????? url??? ?????? ????????? ?????? ?????? ????????? url ???????????????



    def like(self, media_id):
        """ Send http request to like media by ID """
        if self.login_status: 
            try:
                r = self.post_like(media_id)

                if r['status'] == 'ok':
                    like = 1
                else:
                    like = 0
                 
                last_liked_media_id = media_id
            except:
                self.write_log("like ????????????")
                logging.exception("Except on like!")                
                print('except on like')
                like = 0
                #time.sleep(1)
                #self.like(media_id)
            return like
                

    def get_next_url(self): 
        """ ???????????? ????????? ????????? url ??? ????????????. """
        if self.login_status:
            sql = "select * from insta_tag_url_%s where run_yn = 'N' order by write_time asc limit 0,1" %(self.mb_id)                
            self.curs.execute(sql)

            row = self.curs.fetchone()
             
            if row:
                tag_url = row[2]
                return tag_url
            else:
                self.write_log("????????? ??? url ??????")                     
                logging.exception("get_next_url")
                return 0         


    def update_next_url_liked(self, tag_url,result): 
        """ ????????? ????????? ?????? url ????????? Y??? ???????????? """
        if self.login_status:
            now = datetime.datetime.now()
            sql = "update insta_tag_url_%s set run_yn = '%s',update_time =now() where url = '%s'" %(self.mb_id,result,tag_url)                
            self.curs.execute(sql)

            if self.curs:
                #print('url ???????????? y??? ????????? ??????')
                return 1
            else:
                self.write_log("??????!")                    
                logging.exception("?????? y??? ????????? ??????")
                return 0


    def get_next_media_id(self): 
        """ ???????????? ????????? ????????? id ??? ????????????. """
        if self.login_status:
            sql = "select * from insta_tag_url_%s where run_yn = 'N' order by write_time asc  limit 0,1" %(self.mb_id)                
            self.curs.execute(sql)

            row = self.curs.fetchone()
             
            if row:
                media_id = row[11]
                return media_id
            else:
                self.write_log("????????? ??? url ??????")                     
                logging.exception("get_next_media_id")
                return 0


    def get_next_tag(self ): 
        """ ???????????? ????????? ????????? ????????? ???????????? """
        if self.login_status:
##                sql = "select * from insta_tag_%s  where (tag_type <> 'l' or tag_type is null ) order by update_time asc" %(self.mb_id)
                sql = "select tag,tag_type,location_id from insta_tag_%s  order by update_time asc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                

                row = self.curs.fetchone()
                if row:
                    tag = row[0]                    
                    self.tag_type = row[1]  #??????????????? ???????????????...
                    if self.tag_type == None or self.tag_type == '': #??????????????? null(??????,??????)?????? ???????????? ????????????????????? t??? ??????
                        self.tag_type = 't'
                        
                    print ("???????????????:",tag)  
                    print ("?????????????????????:",self.tag_type)
                    if self.tag_type == 'l': #??????????????????
                        location = row[2]
                        self.location_name = row[0]
                        print("??????:",location)
                        
                    now = datetime.datetime.now()
                    sql = "update insta_tag_%s set update_time = now() where tag='%s'" %(self.mb_id,tag)
                    # print (sql) 
                    self.curs.execute(sql)
                    if self.curs:
                        print('?????? ???????????? ???????????? ?????? ??????')
                        print('??????????????? url ???????????? ??????')
                        if self.tag_type == 't':
                            return tag
                        else:
                            return location
                            
                    else:
                        self.write_log("??????!")                    
                        logging.exception("?????? y??? ????????? ??????")
                        return 0                 
                    
                else:
                    self.write_log("????????? ?????? ??????")                     
                    logging.exception("?????? ???????????? ??????")
                    return 0


    def get_url_by_tag(self, tag,tag_type): 
        """ ????????? ????????? ????????? ????????? ????????? ???????????? ???????????? """
        if self.login_status == 1 and tag != 0:
            log_string = "%s ????????? ????????? url?????? ????????? ?????????." % (tag)                
            self.write_log(log_string) 

            
            self.auto_patch = True
            print("??????:",tag)
            print("????????????:",self.tag_type) 
            
            
            try:
                

                tag_flag = int(self.mb_id_number) % 2

                if tag_flag == 0 : #????????? ????????? ????????? ?????? ?????? ????????? ??????
                    if self.tag_type == 't':
                        self.media_by_tag = self.tag_section(tag,tab='recent',extract=1)   
                        count_edges = len(self.media_by_tag)
                        
                        
                    elif self.tag_type == 'l':

                        self.media_by_tag  = self.location_section(tag , self.generate_uuid(), tab='recent',extract=1)   
                        count_edges = len(self.media_by_tag)
                        tag_type = 'l'
                        tag = self.location_name
                        
                if tag_flag == 1 : #????????? ????????? ????????? ?????? ?????????+????????? ??????
                    if self.tag_type == 't':
                        r = self.feed_tag(tag,self.generate_uuid())  
                        self.media_by_tag = list(r['items'])
                        count_edges = len(self.media_by_tag)
 
                        
                    elif self.tag_type == 'l':

                        #r = self.feed_location(tag)  
                        #self.media_by_tag = list(r['items'])
                        #count_edges = len(self.media_by_tag)
                        #tag_type = 'l'
                        #tag = self.location_name

                        self.media_by_tag  = self.location_section(tag , self.generate_uuid(), tab='recent',extract=1)   
                        count_edges = len(self.media_by_tag)
                        tag_type = 'l'
                        tag = self.location_name

                        
                    



                    


                

                print("???????????? url ?????? :",count_edges)


                
                for i in range(0,count_edges):
                    now = datetime.datetime.now()                    
                    url          = "https://www.instagram.com/p/"+self.media_by_tag[i]['code']+"/"
                    likes        = self.media_by_tag[i]['like_count']
    ##                thumbnail    = self.media_by_tag[i]['carousel_media'][0]['image_versions2']['candidates'][1]['url']
                    thumbnail    = ''
                    comment      = self.media_by_tag[i]['user']['pk']                 
                    etc_tag      = self.media_by_tag[i]['pk']                    
                    write_time   = str(now) 
                    tag_type     = tag_type
                    tag_cnt  = 0
                    
                    delete_yn    = 'N'
                                    
                    if self.media_by_tag[i]['caption'] != None : 
                        w            = self.media_by_tag[i]['caption']['text'] 
                        tag_cnt = w.count('#') 

                        #???????????? ????????? ??????
                        for k in self.mb_filter_ar:
                            if k != '':
                                if w.count(k) > 0:
                                    print("%s ?????? ??????????????? ??????" %(k))
                                    delete_yn = 'Y'

                    #????????? ??????(??????, ????????????)
                    #??????(?????? ?????? ?????? ??????) ?????? ??????
                    if tag_cnt > self.mb_max_tag:
                        print("%s <= ???????????? %s ??? ????????????????????? ??????" %(tag, self.mb_max_tag))
                        delete_yn = 'Y'

                    if likes > 100:
                        print("?????? ????????? ????????? 100?????? ?????? ???????????? ?????? ??????(???????????? ???????????? ??????)")
                        delete_yn = 'Y'                        
                       

                        

                    if delete_yn == 'N':
                        sql = "insert into insta_tag_url_%s set tag = '%s', run_yn = 'N', url = '%s', likes = '%s', thumbnail = '%s', write_time = now(), tag_type= '%s', etc_tag='%s', comment='%s' on duplicate key update tag_type ='%s'" \
                              %(self.mb_id,tag,url,likes,thumbnail,tag_type,etc_tag,comment,tag_type)
                        #print(sql)
                        self.curs.execute(sql)
                        if self.curs:
                            aa = 1
                            #print('%d : %s ????????? url??? db insert ??????'%(i,url)) 
                        else:
                            print('????????? url??? db insert ??????',i) 
                    
            except:                
                self.write_log("get_url_by_tag ??????")
                logging.exception("get_url_by_tag ??????")
                if self.like_error_400 > 10:                        
                    self.write_log("10??? ?????? ????????? ????????? ???????????? ?????? ??????(get_url_by_tag)")
                    quit() 
                self.write_log("????????? ????????? ?????? ??????????????? ????????? ??????(get_url_by_tag")
                write_log  = self.mb_id + " ("+self.proxy + " )"+ str(self.like_counter)
                self.write_log(write_log)
                self.like_error_400 += 1                
        else:
            print("????????? ????????? ????????? ????????? ????????? ????????????")
            return 0
                


    def get_last_tag(self): 
        """???????????????  ????????? ?????? ????????? tag??? ????????????. """
        if self.login_status:
                sql = "select tag from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_tag = row[0]
                    print("???????????????????????????:",last_tag)
                    return last_tag
                else:
                    self.write_log("get_last_media_id error")                     
                    logging.exception("get_last_media_id error")
                    return 0



    def get_user_relationship(self,user_id): 
        """ ????????? ???????????? ????????? ??????????????? ???????????? ????????? ?????? ???????????? ????????????. """

        if self.login_status == 1:
           
            try:
                user_info = self.friendships_show(user_id)        
                log_string = "?????? ?????? ??????????????? .."
                self.write_log(log_string)
                

                


                time.sleep(randint(3,5))

                follower_info = self.user_info(user_id)


                followed_by_viewer = user_info['following']  
                follows_viewer = user_info['followed_by']
                follower = follower_info['user']['follower_count']
                following = follower_info['user']['following_count'] 

                user_name = follower_info['user']['username']
                user_id = follower_info['user']['pk']      
                
                print("??????????????? :",user_name)
                print("??????????????? :",user_id)
                print("????????? :",follower)
                print("????????? :",following)
                print("?????? ?????? ????????? ??????????????? :",followed_by_viewer)
                print("???????????? ?????? ????????? ????????? :",follows_viewer)

                print("????????? ?????? ???????????????:",self.mb_follower_max)

                if followed_by_viewer == False and follows_viewer == False and follower < self.mb_follower_max and following < self.mb_follower_max and follower > 50 and following > 50:
                    print("??????????????????!")
                    return 1 # ???????????? ????????? ???????????? ???????????? ??????(???????????? ?????????)?????? ?????? ??????
                else:

                    print("???????????? ???????????? ???????????? ?????? ????????? ?????? ??????????????? ????????? ?????????")
                    return 0 
                
            except:                
                self.write_log("get_user_relationship ??????")
                logging.exception("get_user_relationship ??????")                




    def update_last_url_time(self): 
        """ ??????????????? ??????(?????????,??????)??? ????????? ??????????????? 10????????????  ??? ?????????  """
        if self.login_status:

                sql = "select url from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)
                row = self.curs.fetchone()
                tag_url = row[0]

                now = datetime.datetime.now()
                td = timedelta(days=-3650)
                
                sql = "update insta_tag_url_%s set run_yn = 'Y', likes = likes+10000 where url = '%s'" %(self.mb_id, tag_url)                
                self.curs.execute(sql)
 
                 
                if self.curs:
                    print(tag_url)
                    print("????????? ????????? ?????? ???????????? 10???????????? ????????? ??????!")
                    return 1
                else:
                    self.write_log("update_last_url_time ??????")                     
                    logging.exception("update_last_url_time ??????")
                    return 0



    def follow_action(self,user_id): 
                    
        print("????????????:",user_id)
        if time.time() > self.iteration_next_follow:   #?????? ???????????? ?????????            
            follow = self.follow(user_id)            
            if follow != 0:                              
                self.follow_error_400 = 0                    
                log_string = "????????? ??????!"                        
                self.iteration_next_follow =  0                    
                self.write_log(log_string)

                return 1
            else:
                log_string = "????????? ?????? ???"                    
                self.write_log(log_string)
                
                # Some error. If repeated - can be ban!
                if self.follow_error_400 >= self.follow_error_400_to_ban:
                    # Look like you banned!
                    print("????????? ?????? ????????? ??????")
                    self.iteration_next_follow = time.time() +  self.add_time(self.follow_error_400_to_ban_time) #????????? ?????? ????????? ?????? ?????? ???
                    self.write_log("?????? ?????? ??????")
                    #self.idle_minute(60,'?????? ?????? ??????')
                else:
                    self.follow_error_400 += 1
                return 0
 
        else :
            
            print("?????? ?????? ?????????.. ???????????? : ",self.iteration_next_follow-time.time())
            self.write_log("?????? ?????? ?????? ????????? ?????? %s" %(self.iteration_next_follow-time.time()))


    def follow(self, user_id):
        """ Send http request to follow """
        if self.login_status: 
            try:
                follow = self.friendships_create(user_id)
                if follow['status'] == 'ok':
                    self.follow_counter += 1
                    log_string = "Followed: %s #%i." % (user_id,
                                                        self.follow_counter)
                    self.write_log(log_string)
    ##                    username = self.get_username_by_user_id(user_id=user_id)
    ##                    insert_username(self, user_id=user_id, username=username)
                return 1
            except:
                self.write_log("follow ????????????")
                logging.exception("Except on follow!")
        return False



    def unfollow(self, user_id):
        """ Send http request to unfollow """
        if self.login_status: 
            try:
                unfollow = self.friendships_destroy(user_id)
                if unfollow['status'] == 'ok':
                    self.unfollow_counter += 1
                    log_string = "Unfollowed: %s #%i." % (user_id,
                                                          self.unfollow_counter)
                    self.write_log(log_string)
                return 1
            except:
                self.write_log("unfollow ????????????")
                logging.exception("Exept on unfollow!")
        return False


    def unfollow_action(self): 
                    
        print("????????????")
        if time.time() > self.iteration_next_unfollow:   #?????? ???????????? ?????????
            print("??????????????? ????????? ??????")
            sql = "select revenge_id,revenge_username from insta_revenge_%s where state <> 'unfollow' order by write_time asc  limit 0,1" %(self.mb_id)                
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            if row != None:
                revenge_id = row[0]
                revenge_username = row[1]
                sql = "update insta_revenge_%s set state = 'unfollow' where revenge_id = '%s'" %(self.mb_id,revenge_id)                
                self.curs.execute(sql)            
                print("????????? ??????:%s"%(revenge_username))
                unfollow = self.unfollow(revenge_id) 
                if unfollow != 0: 
                    self.unfollow_error_400 = 0                    
                    log_string = "%s ???????????? ??????!" %(revenge_username)
                    self.iteration_next_unfollow =  0                        
                    self.write_log(log_string)

                    return 1
                else:
                    log_string = "???????????? ?????? ???"                    
                    self.write_log(log_string)
                    
                    # Some error. If repeated - can be ban!
                    if self.unfollow_error_400 >= self.unfollow_error_400_to_ban:
                        # Look like you banned!
                        print("???????????? ?????? ????????? ??????")
                        self.iteration_next_unfollow = time.time() +  self.add_time(self.unfollow_error_400_to_ban_time) #????????? ?????? ????????? ?????? ?????? ???
                        self.write_log("?????? ?????? ??????")
                        #self.idle_minute(60,'?????? ?????? ??????')
                    else:
                        self.unfollow_error_400 += 1
                    return 0

            else:
                return False
        else :
            print("?????? ?????? ?????????.. ???????????? : ",self.iteration_next_unfollow-time.time())    



    def get_last_user_id(self): 
        """ ??????????????? ????????? ????????? ????????? ???????????? ????????????. """
        if self.login_status:
                sql = "select comment from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_user_id = row[0]
                    return last_user_id
                else:
                    self.write_log("get_last_user_id ??????")                     
                    logging.exception("get_last_user_id ??????")
                    return 0



    def comment_action(self): 
                    
        print("????????????????????????:")
        if time.time() > self.iteration_next_comments:   #?????? ???????????? ?????????

            comment_content = self.get_next_comment()
            if comment_content != 0:                
                comment = self.comment(self.get_last_media_id(),comment_content)
            else:
                print("?????????????????? ?????? ????????? 200?????? ?????? ??????")
                return 1
            if comment != 0: 
                self.comment_error_400 = 0                    
                log_string = "comment ??????!"
                self.iteration_next_comments =  0                    
                self.write_log(log_string)

                return 1
            else:
                log_string = "comment ?????? ???"                    
                self.write_log(log_string)
                
                # Some error. If repeated - can be ban!
                if self.comment_error_400 >= self.comment_error_400_to_ban:
                    # Look like you banned!
                    print("comment ?????? ????????? ??????")
                    self.iteration_next_comments = time.time() +  self.add_time(self.comment_error_400_to_ban_time) #????????? ?????? ????????? ?????? ?????? ???
                    #self.idle_minute(60,'????????? ?????? ??????')
                else:
                    self.comment_error_400 += 1
                return 0
 
        else :
                print("????????? ?????? ?????????.. ???????????? : ",self.iteration_next_comments-time.time())



    def comment(self, media_id, comment_text):
        """ Send http request to comment """
        if self.login_status: 
            try:
                self.test_comment = comment_text
    ##            print("media_id",media_id)
    ##            print("comment_text",comment_text)
    ##            print("gen:",gen_user_breadcrumb(len(comment_text)))
    ##            comment_post = {'comment_text': 'good'}
                comment = self.post_comment(media_id, comment_text)
                if comment['status'] == 'ok':
                    self.comments_counter += 1
                    log_string = 'Write: "%s". #%i.' % (comment_text,
                                                        self.comments_counter)
                    # self.write_log(log_string)
                return 1
            except:
                self.write_log("comment ????????????")
                logging.exception("Except on comment!")
        return False



    def get_next_comment(self): 
        """ ????????? ????????? ?????? ????????? ??? ???????????? ????????????. """
        if self.login_status:

                last_url = self.get_last_url()
                
                sql = "select tag from insta_tag_url_%s where url='%s' and run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id,last_url)                
                self.curs.execute(sql)
                row = self.curs.fetchone()
                comment_tag = row[0]

                sql = "select comment,update_time from insta_tag_comment_%s where comment_tag='%s' order by update_time asc  limit 0,1" %(self.mb_id,comment_tag)                
                self.curs.execute(sql)
                row = self.curs.fetchone()
                print("????????? ????????? ?????? ??????:",comment_tag)

                if row:
                    return_comment = row[0]
                    print("[%s] ?????? ??????????????? ????????? " %(comment_tag))

                    now = datetime.datetime.now()
                    sql = "update insta_tag_comment_%s set update_time = now() where comment_tag='%s' order by update_time asc limit 1" %(self.mb_id,comment_tag)
                    #print(sql)
                    self.curs.execute(sql)
                    
                    return return_comment
                else:
                    sql = "select comment,update_time from insta_tag_comment_%s where comment_tag is null order by update_time asc  limit 0,1" %(self.mb_id)                
                    self.curs.execute(sql)
                    row = self.curs.fetchone()

                    if row: #?????? ?????? ???????????? ????????? 
                        return_comment = row[0]
                        now = datetime.datetime.now()
                        sql = "update insta_tag_comment_%s set update_time = now() where comment_tag is null order by update_time asc limit 1" %(self.mb_id)                
                        print(sql)
                        self.curs.execute(sql)
                        print("??????????????? ?????????") 
                        
                    else: #?????? ?????? ???????????? ?????????
                        print("?????? ?????? ???????????? ??????")
                        return_comment = 0

                    return return_comment    
        


    def get_last_media_id(self): 
        """???????????????  ????????? ?????? ????????? media_id ??? ????????????. """
        if self.login_status:
                sql = "select etc_tag from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    media_id = row[0]
                    return media_id
                else:
                    self.write_log("get_last_media_id error")                     
                    logging.exception("get_last_media_id error")
                    return 0


    def get_last_url(self): 
        """ ??????????????? ????????? ????????? url ????????????. """
        if self.login_status:
                sql = "select url from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_url = row[0]
                    return last_url
                else:
                    self.write_log("get_last_url ??????")                     
                    logging.exception("get_last_url ??????")
                    return 0                




    def get_follower(self): 
        """ ????????? ???????????? ????????? ?????? ??????."""

        follower_cnt = ''

        if time.time() > self.iteration_next_get_follower:        
            sql = "select * from insta_follower_list where run_time = 0 and type='follower' order by write_time asc  limit 0,1"               
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            today = datetime.datetime.today().strftime("%Y%m%d")
            now = datetime.datetime.now()

            if row != None: #????????? ???????????? ?????????
                day = row[0]
                run_time = row[1]
                after = row[2]
                before_after = row[2]
                target_insta_id = row[3]
                target_mb_id = row[4]
                run_mb_id = row[5]
                follower = row[6]
                following = row[7]
     
                if after == '': #???????????? ??????????????????
                    print("???????????? ????????? ??????(????????? ?????? ?????????)")
                    sql = "delete from insta_follower_%s" %(target_mb_id)
                    self.curs.execute(sql)  
##                    try:      
                        

                    follower_info = self.user_info(target_insta_id)
                    time.sleep(randint(1,5)) 
                    follower = follower_info['user']['follower_count']
                    following = follower_info['user']['following_count'] 
                    print("????????? :",follower)
                    print("????????? :",following)
                    
                    sql = "update insta_follower_list set run_time = now(), follower = '%s', following = '%s', run_mb_id = '%s' where day ='%s' and target_mb_id = '%s' and after = '' and type='follower'  and run_time = 0" \
                          %(follower,following,self.mb_id,day, target_mb_id)
                    print("sql:",sql)
                    self.curs.execute(sql)  #?????????????????? ???????????? ????????? update

                    sql = "update g5_member set real_follower = '%s', real_following = '%s' where mb_id = '%s'" \
                          %(follower, following, target_mb_id)              
                    self.curs.execute(sql)  #?????? ????????? ????????? ????????????
     
                        
##                    except:                
##                        self.write_log("get_user_relationship ??????")
##                        logging.exception("get_user_relationship ??????")
                     
                
                if self.login_status: 
                    log_string = "%s?????? ????????? ???????????? ??????  " % (target_mb_id)
                    
                    self.write_log(log_string)
                    if self.login_status == 1:                     
                        try:
                            print("target_insta_id:",target_insta_id)
                            print("genere:",self.generate_uuid())
                            print("after:",after)
                            r = self.user_followers(target_insta_id,self.generate_uuid(),max_id=after)
                             
                            follower_json = list(r['users'])
                            

                            for i in range(0,len(follower_json)):                        
                                #print(follower_json[i]['node']['username'])
                                follower_username = follower_json[i]['username']
                                follower_user_id = follower_json[i]['pk']
                                follower_profile = follower_json[i]['profile_pic_url']
                                sql = "insert into insta_follower_%s set state = 'new', follower_day ='%s', follower_id='%s', follower_username ='%s',follower_profile_picture='%s',write_time=now()  on duplicate key update state='new'"\
                                      %(target_mb_id, today, follower_user_id, follower_username, follower_profile)
                                self.curs.execute(sql)

                            sql = "select real_follower as cnt from g5_member where mb_id = '%s'" %(target_mb_id)              
                            self.curs.execute(sql) 
                            row = self.curs.fetchone()
                            follower_cnt = row[0]


                            has_next_page = r['big_list']
                            if has_next_page:
                                after = r['next_max_id']
                                
                            sql = "select count(1) cnt from insta_follower_%s" %(target_mb_id)              
                            self.curs.execute(sql) 
                            row = self.curs.fetchone()
                            cnt = row[0]
                            print("??????            ????????? ?????? :",follower_cnt)
                            print("???????????? ????????? ????????? ?????? :",cnt)
                            if has_next_page and int(follower_cnt) > int(cnt):
                                print("??????????????? ???????????????")
                                #????????? ??????????????? ????????? Y??? ????????????...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='follower'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #?????? ?????????????????? ????????? Y??? ????????????                        
                                sql = "insert into insta_follower_list set day = '%s', run_time = 0,after = '%s', target_insta_id = '%s', target_mb_id='%s',run_mb_id ='%s',follower='%s',following='%s',type='follower' on duplicate key update day='%s'" %(today,after,target_insta_id,target_mb_id,self.mb_id,follower,following,today)                                          
                                self.curs.execute(sql)  #???????????? ????????? ???????????? ????????????
                            else:
                                print("???????????????")
                                #????????? ??????????????? ????????? Y??? ????????????...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='follower'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #?????? ?????????????????? ????????? Y??? ????????????


                            # ????????? ????????? ,????????? ???????????? ??????
                            sql = "update g5_member set get_follower = (select count(1) from insta_follower_%s), get_following = (select count(1) from insta_following_%s) where mb_id = '%s'" \
                                      %(target_mb_id,target_mb_id,target_mb_id)              
                            self.curs.execute(sql)
                            self.get_follower_error_400 = 0

                        except:
                            if self.get_follower_error_400 >= self.get_follower_error_400_to_ban:
                                # Look like you banned!
                                print("????????? ???????????? ?????? ??????")
                                self.iteration_next_get_follower = time.time() +  self.add_time(self.get_follower_error_400_to_ban_time) #????????? ?????? ????????? ?????? ?????? ???
                                #self.idle_minute(60,'?????? ?????? ??????')
                            else:
                                self.get_follower_error_400 += 1
                                
                            self.write_log("Except on get_follower!")
                            logging.exception("get_follower_error")
                    else:
                        return 0
        else:
            print("?????? get follower api ????????????")




    def get_following(self): 
        """ ????????? ???????????? ????????? ?????? ??????."""

        following_cnt = ''

        if time.time() > self.iteration_next_get_following:        
            sql = "select * from insta_follower_list where run_time = 0 and type='following' order by write_time asc  limit 0,1"               
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            today = datetime.datetime.today().strftime("%Y%m%d")
            now = datetime.datetime.now()

            if row != None: #????????? ???????????? ?????????
                day = row[0]
                run_time = row[1]
                after = row[2]
                before_after = row[2]
                target_insta_id = row[3]
                target_mb_id = row[4]
                run_mb_id = row[5]
                follower = row[6]
                following = row[7]
     
                if after == '': #???????????? ??????????????????
                    print("???????????? ????????? ??????(????????? ?????? ?????????)")
                    sql = "delete from insta_following_%s" %(target_mb_id)
                    self.curs.execute(sql)  
##                    try:      
                        

                    following_info = self.user_info(target_insta_id)
                    time.sleep(randint(1,5)) 
                    following = following_info['user']['following_count']
                    follower = following_info['user']['follower_count'] 
                    print("????????? :",follower)
                    print("????????? :",following)
                    sql = "update insta_follower_list set run_time = now(), follower = '%s', following = '%s', run_mb_id = '%s' where day ='%s' and target_mb_id = '%s' and after = '' and type='following' and run_time = 0" \
                          %(follower,following,self.mb_id,day, target_mb_id)
                    print("sql:",sql)
                    self.curs.execute(sql)  #?????????????????? ???????????? ????????? update

                    sql = "update g5_member set real_follower = '%s', real_following = '%s' where mb_id = '%s'" \
                          %(follower, following, target_mb_id)              
                    self.curs.execute(sql)  #?????? ????????? ????????? ????????????
     
                        
##                    except:                
##                        self.write_log("get_user_relationship ??????")
##                        logging.exception("get_user_relationship ??????")
                     
                
                if self.login_status: 
                    log_string = "%s?????? ????????? ???????????? ??????  " % (target_mb_id)
                    
                    self.write_log(log_string)
                    if self.login_status == 1:                     
                        try:
                            print("target_insta_id:",target_insta_id)
                            print("genere:",self.generate_uuid())
                            print("after:",after)
                            r = self.user_following(target_insta_id,self.generate_uuid(),max_id=after)
                             
                            following_json = list(r['users'])
                            

                            for i in range(0,len(following_json)):                        
                                #print(following_json[i]['node']['username'])
                                following_username = following_json[i]['username']
                                following_user_id = following_json[i]['pk']
                                following_profile = following_json[i]['profile_pic_url']
                                sql = "insert into insta_following_%s set state = 'new', following_day ='%s', following_id='%s', following_username ='%s',following_profile_picture='%s',write_time=now()  on duplicate key update state='new'"\
                                      %(target_mb_id, today, following_user_id, following_username, following_profile)
                                self.curs.execute(sql)

                            sql = "select real_following as cnt from g5_member where mb_id = '%s'" %(target_mb_id)              
                            self.curs.execute(sql) 
                            row = self.curs.fetchone()
                            following_cnt = row[0]


                            has_next_page = r['big_list']
                            if has_next_page:
                                after = r['next_max_id']
                                
                            sql = "select count(1) cnt from insta_following_%s" %(target_mb_id)              
                            self.curs.execute(sql) 
                            row = self.curs.fetchone()
                            cnt = row[0]
                            print("??????            ????????? ?????? :",following_cnt)
                            print("???????????? ????????? ????????? ?????? :",cnt)
                            if has_next_page and int(following_cnt) > int(cnt):
                                print("??????????????? ???????????????")
                                #????????? ??????????????? ????????? Y??? ????????????...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='following'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #?????? ?????????????????? ????????? Y??? ????????????                        
                                sql = "insert into insta_follower_list set day = '%s', run_time = 0,after = '%s', target_insta_id = '%s', target_mb_id='%s',run_mb_id ='%s',following='%s',following='%s',type='following' on duplicate key update day='%s'" %(today,after,target_insta_id,target_mb_id,self.mb_id,following,following,today)                                          
                                self.curs.execute(sql)  #???????????? ????????? ???????????? ????????????
                            else:
                                print("???????????????")
                                #????????? ??????????????? ????????? Y??? ????????????...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='following'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #?????? ?????????????????? ????????? Y??? ????????????


                            # ????????? ????????? ,????????? ???????????? ??????
                            sql = "update g5_member set get_follower = (select count(1) from insta_follower_%s), get_following = (select count(1) from insta_following_%s) where mb_id = '%s'" \
                                      %(target_mb_id,target_mb_id,target_mb_id)              
                            self.curs.execute(sql)
                            self.get_following_error_400 = 0

                        except:
                            if self.get_following_error_400 >= self.get_following_error_400_to_ban:
                                # Look like you banned!
                                print("????????? ???????????? ?????? ??????")
                                self.iteration_next_get_following = time.time() +  self.add_time(self.get_following_error_400_to_ban_time) #????????? ?????? ????????? ?????? ?????? ???
                                #self.idle_minute(60,'?????? ?????? ??????')
                            else:
                                self.get_following_error_400 += 1
                                
                            self.write_log("Except on get_following!")
                            logging.exception("get_following_error")
                    else:
                        return 0
        else:
            print("?????? get following api ????????????")            







    def get_like(self): 
        """ ????????? ?????? ????????? ????????? ?????? ??????."""
        
        sql = "select * from insta_like_list where run_time = 0 and target_mb_id = '%s' order by media_id desc  limit 0,1" %(self.mb_id)
        self.curs.execute(sql) 
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: #????????? ???????????? ?????????
                day = row[0]
                run_time = row[1]
                after = row[2]
                before_after = row[2]
                target_insta_id = row[3]
                target_mb_id = row[4]
                run_mb_id = row[5]
                media_id = row[8]

                sql = "update insta_like_list set run_time = now() where media_id = '%s' and target_mb_id = '%s' and run_time = 0" %(media_id,self.mb_id)
                self.curs.execute(sql)

                r = self.media_likers(media_id)

                user_count = r['user_count']
                
                print("media id : ", media_id)
                print("????????????????????? :",user_count)

      

                log_string = "%s??? ????????? ?????????  ???????????? ??????  " % (media_id)
                self.write_log(log_string)

                like_json = list(r['users'])
                real_count = len(like_json)
                log_string = "?????? ??????  : %s" % (user_count)
                self.write_log(log_string)
                log_string = "??? ??????    : %s" % (real_count)
                self.write_log(log_string)

                for i in range(0,len(like_json)):             
                    likes_id       = like_json[i]['pk']
                    likes_usrename = like_json[i]['username'] 
                    sql = "insert into insta_likes_%s set state = 'new', media_id ='%s', likes_day = current_date()+0, likes_id = '%s', likes_username = '%s', write_time=now()  on duplicate key update state='new'"\
                          %(self.mb_id, media_id, likes_id, likes_usrename)
                    self.curs.execute(sql)

                
                sql = "update insta_like_list set user_count = '%s', real_count = '%s', run_time = now() where media_id = '%s' and target_mb_id = '%s' and run_time = 0" %(user_count,real_count,media_id,self.mb_id)
                self.curs.execute(sql)
            
        except:            
                
            self.write_log("?????? ????????? ??????????????? ????????? ")            
            




    def increase_like(self): 
        """ ????????? ??????????????? ?????? ????????? ????????? ?????? ????????????."""
        
        sql = "select count(1) from insta_tag_url_%s where run_yn  = 'Y' and update_time > (SELECT write_time FROM insta_proxy_list_log WHERE mb_id = '%s' and action in ( '???????????????' ,'???????????????') order by write_time desc limit 0,1 )" %(self.mb_id, self.mb_id)
        self.curs.execute(sql) 
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: # ???????????????
                total_count = int(row[0])  #????????? ????????? ????????? ????????? ?????? ?????????????????? ?????? ??????

                print("?????????????????????:",self.mb_likes_limit)
                print("?????? ?????? ??? ????????? ????????? :",total_count)
                

                if total_count >= ( int(self.mb_likes_limit) * 2) + 10 and  int(self.mb_likes_limit) < 603 and  int(self.mb_likes_limit)  != 0 : #??? ????????? ????????? ?????? ????????? ?????? ????????? 2 + 10 ?????? ??????
                   after_count = int(self.mb_likes_limit) + 100

                   if int(self.mb_likes_limit) + 100 > 600 : #600?????? ????????? ????????? 602?????? ??????
                       after_count = 602                       

                   sql = "update g5_member set mb_6 = '%s' where mb_id = '%s' " %(after_count,self.mb_id)
                   self.curs.execute(sql)

                   sql = "insert into insta_proxy_list_log set mb_id ='%s', action='???????????????',  memo = '%s', write_time = now()" \
                        %(self.mb_id, after_count)                
                   self.curs.execute(sql)

                    
                   self.write_log("????????? ?????? %s??? ?????? ??????!!" %(after_count) )
 
            
        except  Exception as ex:             
                
            self.write_log("????????? ?????? ??????????????? ????????? ")
            print(ex)
 


    def auto_upload(self): 
        """ ???????????? ???????????? ??????.."""
        
        sql = "SELECT * FROM `insta_auto_upload_list` WHERE mb_id='%s' and day_time = DATE_FORMAT(now(), '%%Y%%m%%d%%H')  and result='W' limit 0,1" %(self.mb_id)
        self.curs.execute(sql)
        print(sql)
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: #?????? ???????????? ????????? ??????
                day_time = row[0]
                url = row[2]
                tag = row[3] 

                contents = urllib.request.urlopen(url).read()


                result = self.post_photo(contents,(400,400),tag)

                print("?????? ?????? ????????? :",url)
                print("result:",result)
 
                result = result['status'] 
                

                sql = "update insta_auto_upload_list set result_time = now(), result='%s' where mb_id = '%s' and day_time = '%s'" %(result,self.mb_id,day_time)
                self.curs.execute(sql)
 
            
        except  Exception as ex:           
                
            self.write_log("??????(%s) ?????? ????????? ????????? ?????? ???" %(url))
            sql = "update insta_auto_upload_list set result_time = now(), result='F' where mb_id = '%s' and day_time = '%s'" %(self.mb_id,day_time)
            self.curs.execute(sql)
            print(ex)
        
