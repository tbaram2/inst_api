import json
import codecs
import datetime
import os.path
import logging
import argparse
import pymysql
import requests
from random import randint
from instagram_private_api import Client, ClientCompatPatch
try:
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)
except ImportError:
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from instagram_private_api import (
        Client, ClientError, ClientLoginError,
        ClientCookieExpiredError, ClientLoginRequiredError,
        __version__ as client_version)


def to_json(python_object):
    if isinstance(python_object, bytes):
        return {'__class__': 'bytes',
                '__value__': codecs.encode(python_object, 'base64').decode()}
    raise TypeError(repr(python_object) + ' is not JSON serializable')


def from_json(json_object):
    if '__class__' in json_object and json_object['__class__'] == 'bytes':
        return codecs.decode(json_object['__value__'].encode(), 'base64')
    return json_object


def onlogin_callback(api, new_settings_file):
    cache_settings = api.settings 
    with open(new_settings_file, 'w') as outfile:
        json.dump(cache_settings, outfile, default=to_json)
        print('SAVED: {0!s}'.format(new_settings_file))
    

 # mysql과 연동하는 작업
conn = pymysql.connect(host='',user = '',
               password='', db='',charset='utf8')
# user는 본인 계정, password는 본인
curs = conn.cursor() 

conn.query("set character_set_connection=utf8;")
conn.query("set character_set_server=utf8;")
conn.query("set character_set_client=utf8;")
conn.query("set character_set_results=utf8;")
conn.query("set character_set_database=utf8;")

query = "SQL Sentence"
curs.execute("set names utf8")



phone_rnd = randint(0,4)

android_rnd = randint(0,2)

if phone_rnd == 0:
    phone_device = 'SM-G930F'
if phone_rnd == 1:
    phone_device = 'SM-G930S'
if phone_rnd == 2:
    phone_device = 'SM-G960F'
if phone_rnd == 3:
    phone_device = 'SM-G935F'
if phone_rnd == 4:
    phone_device = 'SM-G965N'

if android_rnd == 0:
    android_release = '7.0'
if android_rnd == 1:
    android_release = '7.0'
if android_rnd == 2:
    android_release = '8.0'    

    
cached_settings = ""

print("작업할 아이디 가지고오기...")
today = datetime.datetime.today().strftime("%Y%m%d")
sql = "   \
select a.*   \
from   \
(   \
select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  5 minute) or mb_last_check is null) and    \
                                        (mb_problem_type is null or mb_problem_type = '전번인증' )   \
                                     and mb_3>=current_date()+0   order by mb_last_check asc   \
) a   \
union all   \
select b.*    \
from   \
(   \
select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  360 minute)) and    \
                                        (mb_problem_type = '계정좋아요정지')   \
                                     and mb_3>=current_date()+0    order by mb_last_check asc   \
) b   \
  \
"

total_count = curs.execute(sql)
print("현재 작업중이지 않은 계정 총 %s개 남음" %(total_count))
row = curs.fetchone()
if row != None:
    id = row[0]
    insta_id = row[1]
    s = requests.Session()
    print("선택된 팔로워 플러스 아이디:",id)
    print("인스타아이디:",insta_id)
    sql = "update g5_member set mb_last_check = now() where mb_id = '%s'" %(id)
    curs.execute(sql)    
    s = requests.Session()
    result = s.get("https://www.instagram.com/"+insta_id)
    print(result.status_code)

    mb_id = id
    if result.status_code == 404:
        print("아이디가 존재하지 않음으로 종료(전번인증일 가능성 높음")
        sql = "update g5_member set mb_problem_type ='전번인증',mb_last_error_time = now() where mb_id = '%s' and mb_problem_type is null" %(id)
        r = curs.execute(sql)

        
        if r:
            sql = "insert into insta_proxy_list_log set mb_id ='%s', action='전번인증' , ip = '0', write_time = now()" \
                  %(id)
            curs.execute(sql)
      

        

        
        
        
        # 아이디 선택된 직후에 mb_last_check 업데이트        
        quit()


    
    
    
    
    
    
##    conn.close()

    
else:
    print("작업할 아이디 없음")
    quit()


            
##mb_id = "jinse_lee"

     
print('Client version: {0!s}'.format(client_version))

device_id = None
try:

    settings_file = "session/%s.txt" %(mb_id)
    if not os.path.isfile(settings_file):
        # settings file does not exist
        print('Unable to find file: {0!s}'.format(settings_file))


        print("오래된 아이피 클래스 가져오기")
        #sql = "select class from (SELECT class,max(last_check_in_time) last_check_in_time FROM insta_proxy_list where use_yn = 'Y' and memo like 'aws%%' group by class) a order by a.last_check_in_time asc  limit 0,1"
        sql = "select class from (SELECT class,max(last_check_in_time) last_check_in_time FROM insta_proxy_list where use_yn = 'Y' group by class) a order by a.last_check_in_time asc  limit 0,1"

        curs.execute(sql)        
        row = curs.fetchone()
        last_class = row[0]

        print("오래된 클래스에서 랜덤 아이피 가져오기")
        #sql = "select ip,memo,class from insta_proxy_list where use_yn = 'Y' and class='%s' and memo like 'aws%%' order by last_check_in_time asc,rand()  limit 0,1" %(last_class)
        sql = "select ip,memo,class from insta_proxy_list where use_yn = 'Y' and class='%s'  order by last_check_in_time asc,rand()  limit 0,1" %(last_class)

        
        curs.execute(sql)
        row = curs.fetchone()
        print("ip:",row[0])

        sql = "update insta_proxy_list set last_check_in_time = now(),last_user = '%s' where ip='%s'" %(mb_id,row[0])
        curs.execute(sql)

        # login new
##        api = Client(
##            mb_id
##            , proxy=row[0]
##            , android_release = android_release
##            , phone_device = phone_device,
##            on_login=lambda x: onlogin_callback(x, settings_file))

        api = Client(
            mb_id
            
            , android_release = android_release
            , phone_device = phone_device,
            on_login=lambda x: onlogin_callback(x, settings_file))        

        
    else:  #세션존재
        with open(settings_file) as file_data:
            cached_settings = json.load(file_data, object_hook=from_json)
        print('Reusing settings: {0!s}'.format(settings_file))


        print("오래된 아이피 클래스 가져오기")
        #sql = "select class from (SELECT class,max(last_check_in_time) last_check_in_time FROM insta_proxy_list where use_yn = 'Y' and memo like 'aws%%' group by class) a order by a.last_check_in_time asc  limit 0,1"
        sql = "select class from (SELECT class,max(last_check_in_time) last_check_in_time FROM insta_proxy_list where use_yn = 'Y' group by class) a order by a.last_check_in_time asc  limit 0,1"

        curs.execute(sql)        
        row = curs.fetchone()
        last_class = row[0]

        print("오래된 클래스에서 랜덤 아이피 가져오기")
        #sql = "select ip,memo,class from insta_proxy_list where use_yn = 'Y' and class='%s' and memo like 'aws%%' order by last_check_in_time asc,rand()  limit 0,1" %(last_class)
        sql = "select ip,memo,class from insta_proxy_list where use_yn = 'Y' and class='%s'  order by last_check_in_time asc,rand()  limit 0,1" %(last_class)

        
        curs.execute(sql)
        row = curs.fetchone()
        
        if row:
            proxy = row[0]
            proxy_company = row[1]
            ip_class = row[2]
            print("가져온프록시아이피:",proxy)
            print("가져온프록시아이피:%s (%s)" %(proxy,proxy_company))
            sql = "update insta_proxy_list set last_check_in_time = now(),last_user = '%s' where ip='%s'" %(mb_id,proxy)
            curs.execute(sql)

            if proxy != '':
                sql = "insert into insta_proxy_list_log set mb_id ='%s', action='in', class = '%s', ip = '%s', memo = '%s', write_time = now()" \
                      %(mb_id, ip_class, proxy, proxy_company)
                curs.execute(sql) 
        else:
            proxy = ''
    

        device_id = cached_settings.get('device_id')
        # reuse auth settings
        conn.close()
        api = Client(
            mb_id,
            settings=cached_settings,proxy=proxy)
        api.start()

except (ClientCookieExpiredError, ClientLoginRequiredError) as e:
    print('ClientCookieExpiredError/ClientLoginRequiredError: {0!s}'.format(e))

    # Login expired
    # Do relogin but use default ua, keys and such
    api = Client(
        mb_id,
        device_id=device_id,
        on_login=lambda x: onlogin_callback(x, settings_file))

except ClientLoginError as e:
    print('ClientLoginError {0!s}'.format(e))
    exit(9)
except ClientError as e:
    print('ClientError {0!s} (Code: {1:d}, Response: {2!s})'.format(e.msg, e.code, e.error_response))
    exit(9)
except Exception as e:
    print('Unexpected Exception: {0!s}'.format(e))
    exit(99)

# Show when login expires
cookie_expiry = api.cookie_jar.auth_expires
print('Cookie Expiry: {0!s}'.format(datetime.datetime.fromtimestamp(cookie_expiry).strftime('%Y-%m-%dT%H:%M:%SZ')))

# Call the api
##    results = api.tag_search('cats')
##    assert len(results.get('results', [])) > 0

print('All ok')
 



 
##items = results.get('items', [])
##for item in items:
##    # Manually patch the entity to match the public api as closely as possible, optional
##    # To automatically patch entities, initialise the Client with auto_patch=True
##    ClientCompatPatch.media(item)
##    print(media['code'])
