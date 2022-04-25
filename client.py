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


        print("이니셜라이징 시작")
        self.login_status = 1 

         # mysql과 연동하는 작업
        self.conn = pymysql.connect(host='huswssd-0604.cafe24.com',user = 'tbaram3',
                       password='ghdbsdl7615', db='tbaram3',charset='utf8')
        # user는 본인 계정, password는 본인
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
        print("아이디:",self.username)
        print("비  번:",self.password)
        
        self.auto_patch = kwargs.pop('auto_patch', False)
        self.drop_incompat_keys = kwargs.pop('drop_incompat_keys', False)
        self.api_url = kwargs.pop('api_url', None) or self.API_URL
        self.timeout = kwargs.pop('timeout', 15)
        self.on_login = kwargs.pop('on_login', None)
        self.logger = logger


        print("팝전")
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
        print("팝후")

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

        print("쿠키스트링전")
##        print("cookie:",user_settings.get('cookie'))
        cookie_string = kwargs.pop('cookie', None) or user_settings.get('cookie')
##        print("쿠키자 세팅전 ")
##        cookie_string = to_json(cookie_string)
        cookie_jar = ClientCookieJar(cookie_string=cookie_string)
##        print("쿠키자 세팅후 ")
        if cookie_string and cookie_jar.auth_expires and int(time.time()) >= cookie_jar.auth_expires:
            raise ClientCookieExpiredError('Cookie expired at {0!s}'.format(cookie_jar.auth_expires))
        cookie_handler = compat_urllib_request.HTTPCookieProcessor(cookie_jar)

        proxy_handler = None
##        print("프록시세팅전 ")
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

        print("오프너 생성")

        # ad_id must be initialised after cookie_jar/opener because
        # it relies on self.authenticated_user_name
        self.ad_id = (
            kwargs.pop('ad_id', None) or user_settings.get('ad_id') or
            self.generate_adid())

        print("안드로이드 id 생성")

        

##        print("cookie_string:",cookie_string)
##        print("cookie_jar:",cookie_jar)

        if not cookie_string:   # [TODO] There's probably a better way than to depend on cookie_string
            if not self.username or not self.password:
                print("login_requirede 체크")
                raise ClientLoginRequiredError('login_required', code=400)
            print("로긴직전")
            self.login()

            print("로긴직후")

            r = self.username_info(self.user_login)
            

            self.user_id = r['user']['pk']
            sql = "update g5_member set mb_1 = '%s' where mb_id = '%s'" %(self.user_id,self.mb_id)                
            self.curs.execute(sql)
            time.sleep(3)
            
            
        print("에이전트 생성직전")
        self.logger.debug('USERAGENT: {0!s}'.format(self.user_agent))

        sql = "update g5_member set mb_last_reboot = now(), mb_last_error_time = null where mb_id = '%s'" %(self.mb_id)              
        self.curs.execute(sql)

        print("이니셜라이징")
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
            print("call 오류 code:",e.code)
            print("에러 메시지:",error_response)

            if str(e.code) == '400' or str(e.code) == '403' :
                print("오류기록!")
                #print("response:",error_response)

 
                python_dict = json.loads(error_response)
                if 'message' in python_dict:
                    message = python_dict['message']
                    if message == 'login_required':
                        self.write_log("쿠키 이상으로 기존 쿠키 삭제 후 재접속 시도") 
                        settings_file = "session/%s.txt" %(self.mb_id)
                        os.remove(settings_file)
                        quit()
                
  
                print("python_dict:",python_dict['error_type'])
                if python_dict['error_type'] == 'bad_password' or python_dict['error_type'] == 'checkpoint_challenge_required' :
                    if python_dict['error_type'] == 'bad_password' :
                        mb_problem_type = '비번'
                    elif python_dict['error_type'] == 'checkpoint_challenge_required' :
                        
                                           
                        url = python_dict['challenge']['url']
                        s = requests.Session()     
                        r = s.get(url)
                        finder = r.text.find('SubmitPhoneNumberForm')
                        if finder != -1: 
                            print("전번인증")
                            mb_problem_type = '전번인증'
                        else:
                            print("그외인증")
                            mb_problem_type = '400인증'
                        
     
                    sql = "update g5_member set mb_problem_type ='%s',mb_last_error_time = now(),mb_url = '%s' where mb_id = '%s'" %(mb_problem_type,url, self.mb_id)
    ##                sql = "update g5_member set mb_problem_type ='인증',mb_last_error_time = now() where mb_id = '%s' and mb_problem_type is null" %(self.mb_id)              
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
##        print("로그모드")
        if self.log_mod == 0:
            try:
                now_time = datetime.datetime.now()
                print(now_time.strftime("%d.%m.%Y_%H:%M")  + " " + log_text)
            except UnicodeEncodeError:
                print("Your text has unicode problem!")
        elif self.log_mod == 1:
            now_time = datetime.datetime.now()
            print(now_time.strftime("%d.%m.%Y_%H:%M")  + "["+ self.mb_id +"]" + log_text)
##            print("로그모드1")
            # Create log_file if not exist.
            if self.log_file == 0:
##                print("로그모드2")
                
                self.log_file = 1
                now_time = datetime.datetime.now()
##                print("로그남기기")
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
        while 1: #무한루프
            
            if(mode == 1): #일반모드
                
              
                for q in range(10):

                    version_code = '104766000'
                    new_version_code = int(version_code) + randint(0,890)
                    self.version_code = str(new_version_code)

                    

                    #서비스 종료 됐는지 확인
                    print("서비스 종료일:",self.mb_end_service)
                    if(self.mb_end_service < datetime.datetime.today().strftime("%Y%m%d")):                        
                        print("서비스 기간이 지났습니다.")
                        quit()

                    
                    log_string = "[일반 모드 반복문 시작 (좋아요 30초 3번 반복후 팔로우 1회, 코멘트 1회]"                
                    self.write_log(log_string)

                    #mb_last_check 업데이트
                    now = datetime.datetime.now()                
                    sql = "update g5_member set mb_last_check = now() where mb_id = '%s'" %(self.mb_id)
                    self.curs.execute(sql)


                    #좋아요 수치가 0이 아니가 60 미만이면 60으로 강제 업데이트
                    sql = "update g5_member set mb_6 = '60' where (mb_6 > 0 && mb_6 < 60)" 
                    self.curs.execute(sql)                    


                    #테이블 컬럼 길이 변경(당분간은 유지해야할듯)
                    sql = "alter table insta_likes_%s modify likes_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)

                    sql = "alter table insta_unfollowing_%s modify unfollowing_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)

                    sql = "alter table insta_unfollower_%s modify unfollower_id varchar(100)" %(self.mb_id)                
                    self.curs.execute(sql)
                                      
                    
                    
                    #팔로워플러스에서 정보 가져오기 시작
                    print("개인 설정 다시 불러오기")
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
                        print('중간')
                        self.mb_type = row[53]
                        self.mb_server = row[54]
                        self.mb_giver = row[55]
                        self.mb_follower_max = row[68]
                        self.mb_max_tag = row[71]
                        self.mb_id_number = row[40]
                        self.mb_problem_type = row[78]
                        print('끝 ')
##                        self.mb_user_agent = row[82]

                    #오늘 좋아요 몇개 작업했는지 가져오기
                    # sql = "select count(1) likes_count from insta_tag_url_%s where run_yn ='Y' and tag <> '품앗이' and tag <> '친구관리' and update_time > current_date()+0" %(self.mb_id)
                    sql = "select count(1) likes_count from insta_tag_url_%s where run_yn ='Y' and update_time > current_date()+0" %(self.mb_id)                
                    self.curs.execute(sql)
                    row = self.curs.fetchone()
                    likes_count = row[0]

                    follower_flag = int(self.mb_id_number) % 10
                    
                    print("설정작업시간 : %s ~ %s" %(self.mb_start_time, self.mb_end_time))

                    self.mb_start_time = int(self.mb_start_time)
                    if self.mb_start_time > 0:
                        self.mb_start_time = self.mb_start_time + randint(0,2)
                    self.write_log("시작시간 랜덤 변경:%s"%(self.mb_start_time))                    
                    print("좋아요정지여부:",self.mb_problem_type)
                    print("선팔    여부:",self.mb_auto_follow)
                    print("코멘트  여부:",self.mb_auto_comment)
                    print("친구관리여부:",self.mb_friend_manage)
                    print("품앗이  여부:",self.mb_giver)
                    print("목표 좋아요 갯수    :",self.mb_likes_limit)
                    print("오늘갯수(품앗이빼고):",likes_count)
                    self.write_log("오늘좋아요총갯수:%s"%(likes_count))

                    now = datetime.datetime.now()
                    


##                    #친구관리일 경우 목표 갯수와 상관없이 가동시간이내라면 작동되어야하기 때문에 따로 한개 추가!!
##                    if now.hour >= int(self.mb_start_time) and now.hour <= int(self.mb_end_time):                           
##                           #친구관리가 Y일 경우 친구 사진들을 가지고 온다.
                                 
                        
                    if int(self.mb_likes_limit)>int(likes_count)  and now.hour >= int(self.mb_start_time) and now.hour <= int(self.mb_end_time)   : #목표 좋아요 갯수에 도달 못했으면 반복                    






                        
                        print("친구관리여부:",self.mb_friend_manage)
                        if self.mb_friend_manage == 'Y':
                            self.write_log("친구관리 실행") 
                            self.get_url_friend()               
                        for i in range(2):
                            log_string = "%d번째 좋아하기 시작 " % (i)
                            self.write_log(log_string)
                            #좋아요 함수
                            self.like_action()
                            #팔로워 및 팔로잉 가져오기
##                            self.get_following()
##                            self.get_follower()
                            
                            for k in range(45):
                                time.sleep(1)
                            time.sleep(randint(1,15))


                        #일단 품앗이 사진이나 친구관리 들어간 사진은 코멘트 댓글 작업 확인할필요도 없음
                        if self.get_last_tag() != '품앗이' and self.get_last_tag() != '친구관리':                            
                            #선팔이나 코멘트 작업 가능한지 확인
                            user_id = self.get_last_user_id()
                            relationship = self.get_user_relationship(user_id)
                            #(선팔,댓글) 작업 가능한 계정일 경우에만 
                            if relationship == 1 :
                                print("선팔여부:",self.mb_auto_follow)
                                if self.mb_auto_follow == 'Y': 
                                    self.write_log("선팔여부 Y이기 때문에 팔로우 하기시작 ")                
                                    self.follow_action(user_id)
                                    time.sleep(randint(1,10))
                                    

                                print("코멘트여부:",self.mb_auto_comment)
                                if self.mb_auto_comment == 'Y':                                    
                                    self.write_log("코멘트 남기기 시작 ")
                                    self.comment_action()
                                    time.sleep(randint(1,10))

                                self.update_last_url_time()  #선팔이든 댓글이든 남겼으면 해당 사진은 수정시간을 10년전으로..

                        
                        
                    else :
                        self.write_log("작업시간이 아니거나 오늘 목표 달성해서 100초간 대기")
                        
                        for j in range(100):
                            time.sleep(1)


                    

                    print("언팔시작(언팔은 24시간 항상 진행)")
                    time.sleep(randint(1,10))
                    self.write_log("언팔시도(존재하면)") 
                    self.unfollow_action()

                    #최신포스트가지고오기
                    self.write_log("최신 포스트 가져오기") 
                    self.get_recent_post()
                    time.sleep(randint(1,6))

                    #사진예약업로드실행
                    time.sleep(randint(1,6))
                    self.auto_upload()
                    

                    #중복실행 검사
                    self.write_log("중복실행 검사") 
                    self.check_repeat()

                    #팔로워 및 팔로잉 가져오기
                    ## if 1 == 1:
                    if follower_flag == 1 or follower_flag == 2 or follower_flag == 3 or follower_flag == 4 or follower_flag == 5 :
                        self.write_log("다른사람들 팔로워, 팔로잉 가져오기") 
                        self.get_following()
                        self.get_follower()

                    #좋아요 목록 가져오기
                    self.get_like()

                    self.increase_like()


    def check_repeat(self):
        
        """ 중복실행 체크  """
        print("중복실행 체크")
        sql = "select now()-mb_last_check as last_second from g5_member where mb_id='%s'" %(self.mb_id)                
        self.curs.execute(sql)
        row = self.curs.fetchone()
        last_second = row[0]
        print("마지막 last_check :%s 초 전"%(last_second))
        if(last_second < 100):
            print("중복실행의심으로 인한 프로그램을 종료:",last_second)
            quit()    




    def add_time(self, time):
        """ Make some random for next iteration"""
        return time * 0.9 + time * 0.2 * random.random()


    def get_recent_post(self): 
        """ 최신 포스트를 가지고 온다."""
  
        try:
            if time.time() > self.iteration_next_recent:
                self.iteration_next_recent = time.time() +  self.add_time(3600) + randint(1,600)  #1시간 마다 한번씩 실행된다.
                print("최신 포스트 업데이트 하고 username업데이트 하고 통계자료 넣는다.")

                #10번 돌릴때마다 userid로 username을 새롭게 업데이트 하기 위해서(자꾸 아이디 바꾸는 놈들땜시..)
                print("user_id:",self.mb_id_number)
                r = self.user_info(self.mb_id_number)
                user_name = r['user']['username']
                self.user_login = user_name
                if user_name != False:
                    print("이름업데이트:",user_name)
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

                    self.write_log("현재팔로워:%s" %(follower))
                    self.write_log("현재팔로잉:%s" %(following)) 

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
                            
                            if i == 0 and self.mb_giver == 'Y': #최신 사진은 품앗이 목록에 넣는다.(품앗이 Y인 사람들만)
                                sql = "select count(1) as cnt from insta_auto_like where mb_id = '%s' and day = current_date()+0 "\
                                      %(self.mb_id)
                                self.curs.execute(sql)
                                row = self.curs.fetchone()
                                cnt = row[0]
                                print("cnt:",cnt)

                                #기존에 품앗이 이미 넣은 사진인지 확인
                                sql = "select count(1) as exist from insta_auto_like where pic_url = '%s'"\
                                      %(media_link)
                                self.curs.execute(sql)
                                row = self.curs.fetchone()
                                exist = row[0]
                                print("exist:",exist)
                                if cnt == 0 and exist == 0: #오늘 아직 품앗이를 안넣었음 품앗이 넣자(그리고 기존에 품앗이 넣은 사진도 아님..
                                    
                                    sql = "insert into insta_auto_like set mb_id = '%s', day = current_date()+0 , pic_url = '%s',write_time=now() "\
                                          %(self.mb_id,media_link)
                                    print("품앗이 넣는 사진 : ",media_link)
                                    self.curs.execute(sql)
                                    #실제품앗이 들어가는 부분
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
                                        sql = "insert into insta_tag_url_%s set tag='품앗이', run_yn='N', comment = '%s', etc_tag = '%s', url='%s', likes=0,tag_type='t', write_time=now() on duplicate key update run_yn='N' "\
                                              %(mbid,self.user_id,media_id,media_link)
##                                        print(sql)
                                        self.curs.execute(sql)
                                        total_cnt = total_cnt+1

                                    print(total_cnt)
                                        

                                    
                                    
                                    
                                else:
                                    print("오늘은 이미 품앗이 넣었거나 신규사진이 없음")
            else:
                print("다음 최신 포스트 가져올때까지 시간남음(초):",self.iteration_next_recent - time.time() )
                self.write_log("다음 최신 포스트 가져올때까지 시간남음")
                
        except  Exception as ex:                    

            if self.get_recent_error_400 > self.get_recent_error_400_to_ban:
                self.write_log("최신 포스트 가져오기 오류 이상으로 프로그램 종료")
                quit()
            else :
                self.get_recent_error_400 = self.get_recent_error_400+1
                
            self.write_log("최신 포스트 가져오다가 오류남 ")
            print(ex)





    def get_url_friend(self): 
        """ 친구들의 최근 올린 사진들을 가지고 옵니다. """
        if self.login_status == 1:
            log_string = "%s 친구들 최근 사진을(피드) 가지고 옵니다." % (self.mb_id)                
            self.write_log(log_string)      
            
            try:
                     
                r = self.feed_timeline() 
                self.media_from_friend = list(r['feed_items'])            
                count_edges = len(self.media_from_friend)
                print("총가져온 피드 갯수 :",count_edges)
                if "media_or_ad" in self.media_from_friend[0]: 
                    if "code" in self.media_from_friend[0]['media_or_ad'] and "injected" not in self.media_from_friend[0]['media_or_ad']: 
                        tag          = '친구관리'                    
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
                            print('최신피드에서 가져온 사진 : %s'%(url)) 
                        else:
                            print('가져온 url을 db insert 실패',i)


                #사진은 두개씩 넣기
                if "media_or_ad" in self.media_from_friend[1]:
                    if "code" in self.media_from_friend[1]['media_or_ad'] and "injected" not in self.media_from_friend[1]['media_or_ad']: 
                        tag          = '친구관리'                    
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
                            print('최신피드에서 가져온 사진 : %s'%(url)) 
                        else:
                            print('가져온 url을 db insert 실패',i)                     
                    
            except:
                self.write_log("get_url_friend 실패")
                logging.exception("get_url_friend 실패")
        else:
            return 0                    




    def like_action(self):
        next_url = self.get_next_url()
        media_id = self.get_next_media_id()
        if (next_url != 0): #가져온 url이 있으면
            print(next_url)
            # print(media_id)
              
            if time.time() > self.iteration_next_like:   #좋아요 정지 먹었으면 안돌아
                
                like = self.like(media_id)
                log_string = "(%d) 라이크 하기전 실패 횟수 " \
                                 % (self.like_error_400)

                self.write_log(log_string)
                
                if like == 1:  
                        self.iteration_next_like = 0 #좋아요 정지 풀렸다고 간주                        
                        self.update_next_url_liked(next_url,'Y') ## run_yn 을 Y로 변경
                        self.like_error_400 = 0
                        self.like_counter += 1
                        log_string = "Liked: %s. Like #%i. %s" % \
                                     (media_id,
                                      self.like_counter,next_url)                    
                        self.write_log(log_string) 
                        print("like썽공: %i 개"%(self.like_counter))

                        sql = "update g5_member set like_check = '0', mb_problem_type = null where mb_id = '%s'" %(self.mb_id)
                        self.curs.execute(sql)                        
                else: 
                    self.update_next_url_liked(next_url,'F') ## run_yn 을 F로 변경
                    log_string = "(%d)좋아요실패ㅠ: %s.  " \
                                 % (self.like_error_400, next_url)

                    self.write_log(log_string)                    
                    # Some error. If repeated - can be ban!
                    if self.like_error_400 >= self.like_error_400_to_ban: # 아이피 5번 연속 좋아요 정지면 아이피 바꾸기
                        print("좋아요 에러 누적 횟수 : ",self.like_error_400)
                        self.write_log("계정 좋아요 블락 먹은듯. 일단 종료 합니다.")

                        sql = "select like_check from g5_member where mb_id = '%s'" %(self.mb_id)                
                        self.curs.execute(sql)
                        row = self.curs.fetchone()
                        like_check = row[0]
                        if like_check != '1':
                            sql = "update g5_member set like_check = '1' where mb_id = '%s'" %(self.mb_id)
                            self.curs.execute(sql)
                            self.write_log("최초 5번 연속 종료 일단 전번인증일수도 있으니 프로그램 종료")
                        else:



                            if self.mb_problem_type != '계정좋아요정지' :
                                sql = "update g5_member set mb_6 = round(mb_6 * 0.5)  where mb_id = '%s'" %(self.mb_id)                
                                self.curs.execute(sql)  #최초 계정좋아요 정지시에 좋아요 수치를 절반으로 줄임(중복으로 정지시에는 안줄임)
  
                                after_count = int(self.mb_likes_limit)*0.5
                 

                                sql = "insert into insta_proxy_list_log set mb_id ='%s', action='좋아요조정',  memo = '%s(하향)', write_time = now()" \
                                    %(self.mb_id, after_count)                
                                self.curs.execute(sql)

                                
                                self.write_log("좋아요 수치 %s로 하향 조정!!" %(after_count) )                                

                                   
                                
                                sql = "update g5_member set mb_last_error_time = now(), mb_problem_type ='계정좋아요정지' where mb_id = '%s'" %(self.mb_id)                
                                self.curs.execute(sql)

                                
                                
                            self.write_log("10번 연속 종료임 계정좋아요정지일 가능성 높음. 프로그램 종료후 확인전까지 로그인 안함")

                            sql = "insert into insta_proxy_list_log set mb_id ='%s', action='좋아요정지', class = '%s', ip = '%s', memo = '%s', write_time = now(), memo2 = '%s'" \
                                  %(self.mb_id, '', self.proxy, '', '')                
                            self.curs.execute(sql)      
                        quit() 
                    else:
                        self.like_error_400 += 1
                        # self.change_proxy()
     
             
            else:
                print("좋아요 정지 상태임.. 남은시간 : ",self.iteration_next_like-time.time())
            
        else: 
            self.get_url_by_tag(self.get_next_tag(),'t')  #더이상 작업할 url이 없기 때문에 다음 차례 태그로 url 가져와야함



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
                self.write_log("like 오류발생")
                logging.exception("Except on like!")                
                print('except on like')
                like = 0
                #time.sleep(1)
                #self.like(media_id)
            return like
                

    def get_next_url(self): 
        """ 다음으로 좋아요 작업할 url 을 가져온다. """
        if self.login_status:
            sql = "select * from insta_tag_url_%s where run_yn = 'N' order by write_time asc limit 0,1" %(self.mb_id)                
            self.curs.execute(sql)

            row = self.curs.fetchone()
             
            if row:
                tag_url = row[2]
                return tag_url
            else:
                self.write_log("좋아요 할 url 없음")                     
                logging.exception("get_next_url")
                return 0         


    def update_next_url_liked(self, tag_url,result): 
        """ 좋아요 작업후 해당 url 상태를 Y로 바꿔준다 """
        if self.login_status:
            now = datetime.datetime.now()
            sql = "update insta_tag_url_%s set run_yn = '%s',update_time =now() where url = '%s'" %(self.mb_id,result,tag_url)                
            self.curs.execute(sql)

            if self.curs:
                #print('url 실행상태 y로 바꾸기 성공')
                return 1
            else:
                self.write_log("실패!")                    
                logging.exception("태그 y로 바꾸기 에러")
                return 0


    def get_next_media_id(self): 
        """ 다음으로 좋아요 작업할 id 을 가져온다. """
        if self.login_status:
            sql = "select * from insta_tag_url_%s where run_yn = 'N' order by write_time asc  limit 0,1" %(self.mb_id)                
            self.curs.execute(sql)

            row = self.curs.fetchone()
             
            if row:
                media_id = row[11]
                return media_id
            else:
                self.write_log("좋아요 할 url 없음")                     
                logging.exception("get_next_media_id")
                return 0


    def get_next_tag(self ): 
        """ 다음으로 좋아요 작업할 태그를 가져온다 """
        if self.login_status:
##                sql = "select * from insta_tag_%s  where (tag_type <> 'l' or tag_type is null ) order by update_time asc" %(self.mb_id)
                sql = "select tag,tag_type,location_id from insta_tag_%s  order by update_time asc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                

                row = self.curs.fetchone()
                if row:
                    tag = row[0]                    
                    self.tag_type = row[1]  #태그타입은 전역변수로...
                    if self.tag_type == None or self.tag_type == '': #태그타입에 null(소통,선팔)이나 아무것도 안들어가있으면 t로 세팅
                        self.tag_type = 't'
                        
                    print ("가져온태그:",tag)  
                    print ("가져온태그타입:",self.tag_type)
                    if self.tag_type == 'l': #위치태그라면
                        location = row[2]
                        self.location_name = row[0]
                        print("위치:",location)
                        
                    now = datetime.datetime.now()
                    sql = "update insta_tag_%s set update_time = now() where tag='%s'" %(self.mb_id,tag)
                    # print (sql) 
                    self.curs.execute(sql)
                    if self.curs:
                        print('태그 수정날짜 업데이트 성공 성공')
                        print('해당태그로 url 가져오기 시작')
                        if self.tag_type == 't':
                            return tag
                        else:
                            return location
                            
                    else:
                        self.write_log("실패!")                    
                        logging.exception("태그 y로 바꾸기 에러")
                        return 0                 
                    
                else:
                    self.write_log("가져올 태그 없음")                     
                    logging.exception("태그 가져오기 에러")
                    return 0


    def get_url_by_tag(self, tag,tag_type): 
        """ 태그를 가지고 최신에 올라온 작업할 사진들을 가져온다 """
        if self.login_status == 1 and tag != 0:
            log_string = "%s 태그로 작업할 url들을 가지고 옵니다." % (tag)                
            self.write_log(log_string) 

            
            self.auto_patch = True
            print("태그:",tag)
            print("태그타입:",self.tag_type) 
            
            
            try:
                

                tag_flag = int(self.mb_id_number) % 2

                if tag_flag == 0 : #아이디 넘버가 짝수일 경우 완전 신버전 방식
                    if self.tag_type == 't':
                        self.media_by_tag = self.tag_section(tag,tab='recent',extract=1)   
                        count_edges = len(self.media_by_tag)
                        
                        
                    elif self.tag_type == 'l':

                        self.media_by_tag  = self.location_section(tag , self.generate_uuid(), tab='recent',extract=1)   
                        count_edges = len(self.media_by_tag)
                        tag_type = 'l'
                        tag = self.location_name
                        
                if tag_flag == 1 : #아이디 넘버가 홀수일 경우 구버전+신버전 방식
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

                        
                    



                    


                

                print("총가져온 url 갯수 :",count_edges)


                
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

                        #금지태그 필터링 시작
                        for k in self.mb_filter_ar:
                            if k != '':
                                if w.count(k) > 0:
                                    print("%s 태그 검출되어서 제외" %(k))
                                    delete_yn = 'Y'

                    #필터링 시작(관종, 금지태그)
                    #관종(태그 많이 달은 애들) 빼기 시작
                    if tag_cnt > self.mb_max_tag:
                        print("%s <= 관종태그 %s 를 넘어섰기때문에 제외" %(tag, self.mb_max_tag))
                        delete_yn = 'Y'

                    if likes > 100:
                        print("이미 좋아요 갯수가 100개가 넘은 사진에는 작업 안함(효율성이 떨어지기 때문)")
                        delete_yn = 'Y'                        
                       

                        

                    if delete_yn == 'N':
                        sql = "insert into insta_tag_url_%s set tag = '%s', run_yn = 'N', url = '%s', likes = '%s', thumbnail = '%s', write_time = now(), tag_type= '%s', etc_tag='%s', comment='%s' on duplicate key update tag_type ='%s'" \
                              %(self.mb_id,tag,url,likes,thumbnail,tag_type,etc_tag,comment,tag_type)
                        #print(sql)
                        self.curs.execute(sql)
                        if self.curs:
                            aa = 1
                            #print('%d : %s 가져온 url들 db insert 성공'%(i,url)) 
                        else:
                            print('가져온 url들 db insert 실패',i) 
                    
            except:                
                self.write_log("get_url_by_tag 실패")
                logging.exception("get_url_by_tag 실패")
                if self.like_error_400 > 10:                        
                    self.write_log("10번 넘게 프록시 문제로 타임아웃 나서 종료(get_url_by_tag)")
                    quit() 
                self.write_log("프록시 문제로 인한 타임아웃일 가능성 높음(get_url_by_tag")
                write_log  = self.mb_id + " ("+self.proxy + " )"+ str(self.like_counter)
                self.write_log(write_log)
                self.like_error_400 += 1                
        else:
            print("고객이 등록한 태그가 하나도 없어서 못가져옴")
            return 0
                


    def get_last_tag(self): 
        """마지막으로  좋아요 누른 사진의 tag를 가져온다. """
        if self.login_status:
                sql = "select tag from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_tag = row[0]
                    print("마지막으로누른태그:",last_tag)
                    return last_tag
                else:
                    self.write_log("get_last_media_id error")                     
                    logging.exception("get_last_media_id error")
                    return 0



    def get_user_relationship(self,user_id): 
        """ 사용자 아이디를 넘기면 여러가지를 판단하여 팔로우 가능 상태인지 알려준다. """

        if self.login_status == 1:
           
            try:
                user_info = self.friendships_show(user_id)        
                log_string = "타겟 정보 가져오는중 .."
                self.write_log(log_string)
                

                


                time.sleep(randint(3,5))

                follower_info = self.user_info(user_id)


                followed_by_viewer = user_info['following']  
                follows_viewer = user_info['followed_by']
                follower = follower_info['user']['follower_count']
                following = follower_info['user']['following_count'] 

                user_name = follower_info['user']['username']
                user_id = follower_info['user']['pk']      
                
                print("영문아이디 :",user_name)
                print("숫자아이디 :",user_id)
                print("팔로워 :",follower)
                print("팔로잉 :",following)
                print("내가 이미 팔로잉 하는지여부 :",followed_by_viewer)
                print("상대방이 나를 팔로잉 하는지 :",follows_viewer)

                print("사용자 최대 팔로워기준:",self.mb_follower_max)

                if followed_by_viewer == False and follows_viewer == False and follower < self.mb_follower_max and following < self.mb_follower_max and follower > 50 and following > 50:
                    print("작업가능상태!")
                    return 1 # 팔로잉도 아니고 팔로워도 아니니까 작업(선팔또는 코멘트)해도 좋은 상태
                else:

                    print("상대방이 팔로워랑 팔로잉이 너무 많거나 나의 팔로워거나 팔로잉 상태임")
                    return 0 
                
            except:                
                self.write_log("get_user_relationship 실패")
                logging.exception("get_user_relationship 실패")                




    def update_last_url_time(self): 
        """ 마지막으로 작업(코멘트,선팔)된 사진의 수정시간을 10년전으로  로 바꾼다  """
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
                    print("마지막 작업한 사진 수정시간 10년전으로 바꾸기 성공!")
                    return 1
                else:
                    self.write_log("update_last_url_time 실패")                     
                    logging.exception("update_last_url_time 실패")
                    return 0



    def follow_action(self,user_id): 
                    
        print("선팔시도:",user_id)
        if time.time() > self.iteration_next_follow:   #정지 먹었으면 안돌아            
            follow = self.follow(user_id)            
            if follow != 0:                              
                self.follow_error_400 = 0                    
                log_string = "팔로우 성공!"                        
                self.iteration_next_follow =  0                    
                self.write_log(log_string)

                return 1
            else:
                log_string = "팔로우 실패 ㅠ"                    
                self.write_log(log_string)
                
                # Some error. If repeated - can be ban!
                if self.follow_error_400 >= self.follow_error_400_to_ban:
                    # Look like you banned!
                    print("팔로우 실패 초과로 대기")
                    self.iteration_next_follow = time.time() +  self.add_time(self.follow_error_400_to_ban_time) #지정한 시간 만큼은 기능 작동 안
                    self.write_log("선팔 정지 먹음")
                    #self.idle_minute(60,'선팔 정지 먹음')
                else:
                    self.follow_error_400 += 1
                return 0
 
        else :
            
            print("선팔 정지 상태임.. 남은시간 : ",self.iteration_next_follow-time.time())
            self.write_log("선팔 정지 먹은 상태임 남은 %s" %(self.iteration_next_follow-time.time()))


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
                self.write_log("follow 오류발생")
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
                self.write_log("unfollow 오류발생")
                logging.exception("Exept on unfollow!")
        return False


    def unfollow_action(self): 
                    
        print("언팔시도")
        if time.time() > self.iteration_next_unfollow:   #정지 먹었으면 안돌아
            print("언팔할사람 있는지 확인")
            sql = "select revenge_id,revenge_username from insta_revenge_%s where state <> 'unfollow' order by write_time asc  limit 0,1" %(self.mb_id)                
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            if row != None:
                revenge_id = row[0]
                revenge_username = row[1]
                sql = "update insta_revenge_%s set state = 'unfollow' where revenge_id = '%s'" %(self.mb_id,revenge_id)                
                self.curs.execute(sql)            
                print("언팔할 사람:%s"%(revenge_username))
                unfollow = self.unfollow(revenge_id) 
                if unfollow != 0: 
                    self.unfollow_error_400 = 0                    
                    log_string = "%s 언팔로우 성공!" %(revenge_username)
                    self.iteration_next_unfollow =  0                        
                    self.write_log(log_string)

                    return 1
                else:
                    log_string = "언팔로우 실패 ㅠ"                    
                    self.write_log(log_string)
                    
                    # Some error. If repeated - can be ban!
                    if self.unfollow_error_400 >= self.unfollow_error_400_to_ban:
                        # Look like you banned!
                        print("언팔로우 실패 초과로 대기")
                        self.iteration_next_unfollow = time.time() +  self.add_time(self.unfollow_error_400_to_ban_time) #지정한 시간 만큼은 기능 작동 안
                        self.write_log("언팔 정지 먹음")
                        #self.idle_minute(60,'언팔 정지 먹음')
                    else:
                        self.unfollow_error_400 += 1
                    return 0

            else:
                return False
        else :
            print("언팔 정지 상태임.. 남은시간 : ",self.iteration_next_unfollow-time.time())    



    def get_last_user_id(self): 
        """ 마지막으로 작업된 사진의 사용자 아이디를 가져온다. """
        if self.login_status:
                sql = "select comment from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_user_id = row[0]
                    return last_user_id
                else:
                    self.write_log("get_last_user_id 실패")                     
                    logging.exception("get_last_user_id 실패")
                    return 0



    def comment_action(self): 
                    
        print("코멘트남기기시도:")
        if time.time() > self.iteration_next_comments:   #정지 먹었으면 안돌아

            comment_content = self.get_next_comment()
            if comment_content != 0:                
                comment = self.comment(self.get_last_media_id(),comment_content)
            else:
                print("범용코멘트가 없기 때문에 200으로 찍고 스킵")
                return 1
            if comment != 0: 
                self.comment_error_400 = 0                    
                log_string = "comment 성공!"
                self.iteration_next_comments =  0                    
                self.write_log(log_string)

                return 1
            else:
                log_string = "comment 실패 ㅠ"                    
                self.write_log(log_string)
                
                # Some error. If repeated - can be ban!
                if self.comment_error_400 >= self.comment_error_400_to_ban:
                    # Look like you banned!
                    print("comment 실패 초과로 대기")
                    self.iteration_next_comments = time.time() +  self.add_time(self.comment_error_400_to_ban_time) #지정한 시간 만큼은 기능 작동 안
                    #self.idle_minute(60,'코멘트 정지 먹음')
                else:
                    self.comment_error_400 += 1
                return 0
 
        else :
                print("코멘트 정지 상태임.. 남은시간 : ",self.iteration_next_comments-time.time())



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
                self.write_log("comment 오류발생")
                logging.exception("Except on comment!")
        return False



    def get_next_comment(self): 
        """ 마지막 좋아요 누른 사진에 달 코멘트를 가져온다. """
        if self.login_status:

                last_url = self.get_last_url()
                
                sql = "select tag from insta_tag_url_%s where url='%s' and run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id,last_url)                
                self.curs.execute(sql)
                row = self.curs.fetchone()
                comment_tag = row[0]

                sql = "select comment,update_time from insta_tag_comment_%s where comment_tag='%s' order by update_time asc  limit 0,1" %(self.mb_id,comment_tag)                
                self.curs.execute(sql)
                row = self.curs.fetchone()
                print("마지막 좋아요 누른 태그:",comment_tag)

                if row:
                    return_comment = row[0]
                    print("[%s] 태그 전용코멘트 남기기 " %(comment_tag))

                    now = datetime.datetime.now()
                    sql = "update insta_tag_comment_%s set update_time = now() where comment_tag='%s' order by update_time asc limit 1" %(self.mb_id,comment_tag)
                    #print(sql)
                    self.curs.execute(sql)
                    
                    return return_comment
                else:
                    sql = "select comment,update_time from insta_tag_comment_%s where comment_tag is null order by update_time asc  limit 0,1" %(self.mb_id)                
                    self.curs.execute(sql)
                    row = self.curs.fetchone()

                    if row: #남길 범용 코멘트가 있으면 
                        return_comment = row[0]
                        now = datetime.datetime.now()
                        sql = "update insta_tag_comment_%s set update_time = now() where comment_tag is null order by update_time asc limit 1" %(self.mb_id)                
                        print(sql)
                        self.curs.execute(sql)
                        print("범용코멘트 남기기") 
                        
                    else: #남길 범용 코멘트가 없으면
                        print("남길 범용 코멘트가 없음")
                        return_comment = 0

                    return return_comment    
        


    def get_last_media_id(self): 
        """마지막으로  좋아요 누른 사진의 media_id 을 가져온다. """
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
        """ 마지막으로 작업된 사진의 url 가져온다. """
        if self.login_status:
                sql = "select url from insta_tag_url_%s where run_yn = 'Y' and likes < 10000 order by update_time desc  limit 0,1" %(self.mb_id)                
                self.curs.execute(sql)

                row = self.curs.fetchone()
                 
                if row:
                    last_url = row[0]
                    return last_url
                else:
                    self.write_log("get_last_url 실패")                     
                    logging.exception("get_last_url 실패")
                    return 0                




    def get_follower(self): 
        """ 가져올 팔로워가 있는지 체크 한다."""

        follower_cnt = ''

        if time.time() > self.iteration_next_get_follower:        
            sql = "select * from insta_follower_list where run_time = 0 and type='follower' order by write_time asc  limit 0,1"               
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            today = datetime.datetime.today().strftime("%Y%m%d")
            now = datetime.datetime.now()

            if row != None: #가져올 팔로워가 존재함
                day = row[0]
                run_time = row[1]
                after = row[2]
                before_after = row[2]
                target_insta_id = row[3]
                target_mb_id = row[4]
                run_mb_id = row[5]
                follower = row[6]
                following = row[7]
     
                if after == '': #첫번째로 돌리는거라면
                    print("처음으로 돌리는 거임(테이블 한번 비우기)")
                    sql = "delete from insta_follower_%s" %(target_mb_id)
                    self.curs.execute(sql)  
##                    try:      
                        

                    follower_info = self.user_info(target_insta_id)
                    time.sleep(randint(1,5)) 
                    follower = follower_info['user']['follower_count']
                    following = follower_info['user']['following_count'] 
                    print("팔로워 :",follower)
                    print("팔로잉 :",following)
                    
                    sql = "update insta_follower_list set run_time = now(), follower = '%s', following = '%s', run_mb_id = '%s' where day ='%s' and target_mb_id = '%s' and after = '' and type='follower'  and run_time = 0" \
                          %(follower,following,self.mb_id,day, target_mb_id)
                    print("sql:",sql)
                    self.curs.execute(sql)  #처음돌릴때는 팔로워랑 팔로잉 update

                    sql = "update g5_member set real_follower = '%s', real_following = '%s' where mb_id = '%s'" \
                          %(follower, following, target_mb_id)              
                    self.curs.execute(sql)  #리얼 팔로워 팔로잉 업데이트
     
                        
##                    except:                
##                        self.write_log("get_user_relationship 실패")
##                        logging.exception("get_user_relationship 실패")
                     
                
                if self.login_status: 
                    log_string = "%s님의 팔로워 가져오기 시작  " % (target_mb_id)
                    
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
                            print("목표            팔로워 숫자 :",follower_cnt)
                            print("현재까지 가져온 팔로워 숫자 :",cnt)
                            if has_next_page and int(follower_cnt) > int(cnt):
                                print("다음가져올 리스트존재")
                                #모든걸 성공적으로 했으니 Y로 업데이트...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='follower'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #얘가 돌려줄꺼니까 빠르게 Y로 업데이트                        
                                sql = "insert into insta_follower_list set day = '%s', run_time = 0,after = '%s', target_insta_id = '%s', target_mb_id='%s',run_mb_id ='%s',follower='%s',following='%s',type='follower' on duplicate key update day='%s'" %(today,after,target_insta_id,target_mb_id,self.mb_id,follower,following,today)                                          
                                self.curs.execute(sql)  #작업후에 새로운 작업할거 업데이트
                            else:
                                print("모두가져옴")
                                #모든걸 성공적으로 했으니 Y로 업데이트...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='follower'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #얘가 돌려줄꺼니까 빠르게 Y로 업데이트


                            # 가져온 팔로워 ,팔로잉 몇명인지 기록
                            sql = "update g5_member set get_follower = (select count(1) from insta_follower_%s), get_following = (select count(1) from insta_following_%s) where mb_id = '%s'" \
                                      %(target_mb_id,target_mb_id,target_mb_id)              
                            self.curs.execute(sql)
                            self.get_follower_error_400 = 0

                        except:
                            if self.get_follower_error_400 >= self.get_follower_error_400_to_ban:
                                # Look like you banned!
                                print("팔로워 가져오기 정지 먹음")
                                self.iteration_next_get_follower = time.time() +  self.add_time(self.get_follower_error_400_to_ban_time) #지정한 시간 만큼은 기능 작동 안
                                #self.idle_minute(60,'선팔 정지 먹음')
                            else:
                                self.get_follower_error_400 += 1
                                
                            self.write_log("Except on get_follower!")
                            logging.exception("get_follower_error")
                    else:
                        return 0
        else:
            print("현재 get follower api 정지당함")




    def get_following(self): 
        """ 가져올 팔로잉가 있는지 체크 한다."""

        following_cnt = ''

        if time.time() > self.iteration_next_get_following:        
            sql = "select * from insta_follower_list where run_time = 0 and type='following' order by write_time asc  limit 0,1"               
            self.curs.execute(sql) 
            row = self.curs.fetchone()

            today = datetime.datetime.today().strftime("%Y%m%d")
            now = datetime.datetime.now()

            if row != None: #가져올 팔로잉가 존재함
                day = row[0]
                run_time = row[1]
                after = row[2]
                before_after = row[2]
                target_insta_id = row[3]
                target_mb_id = row[4]
                run_mb_id = row[5]
                follower = row[6]
                following = row[7]
     
                if after == '': #첫번째로 돌리는거라면
                    print("처음으로 돌리는 거임(테이블 한번 비우기)")
                    sql = "delete from insta_following_%s" %(target_mb_id)
                    self.curs.execute(sql)  
##                    try:      
                        

                    following_info = self.user_info(target_insta_id)
                    time.sleep(randint(1,5)) 
                    following = following_info['user']['following_count']
                    follower = following_info['user']['follower_count'] 
                    print("팔로워 :",follower)
                    print("팔로잉 :",following)
                    sql = "update insta_follower_list set run_time = now(), follower = '%s', following = '%s', run_mb_id = '%s' where day ='%s' and target_mb_id = '%s' and after = '' and type='following' and run_time = 0" \
                          %(follower,following,self.mb_id,day, target_mb_id)
                    print("sql:",sql)
                    self.curs.execute(sql)  #처음돌릴때는 팔로잉랑 팔로잉 update

                    sql = "update g5_member set real_follower = '%s', real_following = '%s' where mb_id = '%s'" \
                          %(follower, following, target_mb_id)              
                    self.curs.execute(sql)  #리얼 팔로잉 팔로잉 업데이트
     
                        
##                    except:                
##                        self.write_log("get_user_relationship 실패")
##                        logging.exception("get_user_relationship 실패")
                     
                
                if self.login_status: 
                    log_string = "%s님의 팔로잉 가져오기 시작  " % (target_mb_id)
                    
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
                            print("목표            팔로잉 숫자 :",following_cnt)
                            print("현재까지 가져온 팔로잉 숫자 :",cnt)
                            if has_next_page and int(following_cnt) > int(cnt):
                                print("다음가져올 리스트존재")
                                #모든걸 성공적으로 했으니 Y로 업데이트...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='following'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #얘가 돌려줄꺼니까 빠르게 Y로 업데이트                        
                                sql = "insert into insta_follower_list set day = '%s', run_time = 0,after = '%s', target_insta_id = '%s', target_mb_id='%s',run_mb_id ='%s',following='%s',following='%s',type='following' on duplicate key update day='%s'" %(today,after,target_insta_id,target_mb_id,self.mb_id,following,following,today)                                          
                                self.curs.execute(sql)  #작업후에 새로운 작업할거 업데이트
                            else:
                                print("모두가져옴")
                                #모든걸 성공적으로 했으니 Y로 업데이트...
                                sql = "update insta_follower_list set run_time = now() where day ='%s' and run_time = 0 and target_mb_id = '%s' and after = '%s' and type='following'" \
                                      %(today, target_mb_id, before_after)              
                                self.curs.execute(sql)  #얘가 돌려줄꺼니까 빠르게 Y로 업데이트


                            # 가져온 팔로워 ,팔로잉 몇명인지 기록
                            sql = "update g5_member set get_follower = (select count(1) from insta_follower_%s), get_following = (select count(1) from insta_following_%s) where mb_id = '%s'" \
                                      %(target_mb_id,target_mb_id,target_mb_id)              
                            self.curs.execute(sql)
                            self.get_following_error_400 = 0

                        except:
                            if self.get_following_error_400 >= self.get_following_error_400_to_ban:
                                # Look like you banned!
                                print("팔로잉 가져오기 정지 먹음")
                                self.iteration_next_get_following = time.time() +  self.add_time(self.get_following_error_400_to_ban_time) #지정한 시간 만큼은 기능 작동 안
                                #self.idle_minute(60,'선팔 정지 먹음')
                            else:
                                self.get_following_error_400 += 1
                                
                            self.write_log("Except on get_following!")
                            logging.exception("get_following_error")
                    else:
                        return 0
        else:
            print("현재 get following api 정지당함")            







    def get_like(self): 
        """ 좋아요 누른 사람들 목록을 가져 온다."""
        
        sql = "select * from insta_like_list where run_time = 0 and target_mb_id = '%s' order by media_id desc  limit 0,1" %(self.mb_id)
        self.curs.execute(sql) 
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: #가져올 좋아요가 존재함
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
                print("실제좋아요갯수 :",user_count)

      

                log_string = "%s의 좋아요 리스트  가져오기 시작  " % (media_id)
                self.write_log(log_string)

                like_json = list(r['users'])
                real_count = len(like_json)
                log_string = "실제 갯수  : %s" % (user_count)
                self.write_log(log_string)
                log_string = "총 갯수    : %s" % (real_count)
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
                
            self.write_log("최신 포스트 가져오다가 오류남 ")            
            




    def increase_like(self): 
        """ 좋아요 성공정도에 따라 좋아요 수치를 자동 조정한다."""
        
        sql = "select count(1) from insta_tag_url_%s where run_yn  = 'Y' and update_time > (SELECT write_time FROM insta_proxy_list_log WHERE mb_id = '%s' and action in ( '좋아요정지' ,'좋아요조정') order by write_time desc limit 0,1 )" %(self.mb_id, self.mb_id)
        self.curs.execute(sql) 
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: # 존재할경우
                total_count = int(row[0])  #마지막 좋아요 정지나 좋아요 조정 이후로좋아요 성공 횟수

                print("현재목표좋아요:",self.mb_likes_limit)
                print("정지 이후 총 좋아요 카운트 :",total_count)
                

                if total_count >= ( int(self.mb_likes_limit) * 2) + 10 and  int(self.mb_likes_limit) < 603 and  int(self.mb_likes_limit)  != 0 : #총 좋아요 갯수가 설정 좋아요 갯수 곱하기 2 + 10 보다 크면
                   after_count = int(self.mb_likes_limit) + 100

                   if int(self.mb_likes_limit) + 100 > 600 : #600보다 클경우 무조건 602으로 고정
                       after_count = 602                       

                   sql = "update g5_member set mb_6 = '%s' where mb_id = '%s' " %(after_count,self.mb_id)
                   self.curs.execute(sql)

                   sql = "insert into insta_proxy_list_log set mb_id ='%s', action='좋아요조정',  memo = '%s', write_time = now()" \
                        %(self.mb_id, after_count)                
                   self.curs.execute(sql)

                    
                   self.write_log("좋아요 수치 %s로 상향 조정!!" %(after_count) )
 
            
        except  Exception as ex:             
                
            self.write_log("좋아요 수치 조정하다가 오류남 ")
            print(ex)
 


    def auto_upload(self): 
        """ 자동으로 업로드를 한다.."""
        
        sql = "SELECT * FROM `insta_auto_upload_list` WHERE mb_id='%s' and day_time = DATE_FORMAT(now(), '%%Y%%m%%d%%H')  and result='W' limit 0,1" %(self.mb_id)
        self.curs.execute(sql)
        print(sql)
        row = self.curs.fetchone()

        today = datetime.datetime.today().strftime("%Y%m%d")
        now = datetime.datetime.now()

        try:

            if row != None: #자동 업로드할 사진이 있음
                day_time = row[0]
                url = row[2]
                tag = row[3] 

                contents = urllib.request.urlopen(url).read()


                result = self.post_photo(contents,(400,400),tag)

                print("사진 자동 업로드 :",url)
                print("result:",result)
 
                result = result['status'] 
                

                sql = "update insta_auto_upload_list set result_time = now(), result='%s' where mb_id = '%s' and day_time = '%s'" %(result,self.mb_id,day_time)
                self.curs.execute(sql)
 
            
        except  Exception as ex:           
                
            self.write_log("사진(%s) 자동 업로드 하다가 오류 남" %(url))
            sql = "update insta_auto_upload_list set result_time = now(), result='F' where mb_id = '%s' and day_time = '%s'" %(self.mb_id,day_time)
            self.curs.execute(sql)
            print(ex)
        
