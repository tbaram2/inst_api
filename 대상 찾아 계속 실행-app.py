#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import time
import json
import re
import requests
import ctypes
import pymysql
import datetime
import ctypes
import os, subprocess
import _thread
 
from os import system





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


print("작업할 아이디 가지고오기...")
today = datetime.datetime.today().strftime("%Y%m%d")
sql = "   \
select a.*   \
from   \
(   \
select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  5 minute) or mb_last_check is null) and    \
                                        (mb_problem_type is null)   \
                                     and mb_3>=current_date()+0   order by mb_last_check asc   \
) a   \
union all   \
select b.*    \
from   \
(   \
select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  1440 minute)) and    \
                                        (mb_problem_type = '계정좋아요정지')   \
                                     and mb_3>=current_date()+0    order by mb_last_check asc   \
) b   \
  \
"

total_count = curs.execute(sql)
print("현재 작업중이지 않은 계정 총 %s개 남음" %(total_count))
row = curs.fetchone()

cnt = input('몇개실행할까요?:')
autostart = "autostart-app.py"

def os_system(autostart):
    os.system(autostart)


for i in range(int(cnt)):
    _thread.start_new_thread(os_system,(autostart,))
    time.sleep(5)

while 1:


        
    print("작업할 아이디 가지고오기...")
    today = datetime.datetime.today().strftime("%Y%m%d")
    sql = "   \
    select a.*   \
    from   \
    (   \
    select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  5 minute) or mb_last_check is null) and    \
                                        (mb_problem_type is null or mb_problem_type ='전번인증')   \
                                         and mb_3>=current_date()+0   order by mb_last_check asc   \
    ) a   \
    union all   \
    select b.*    \
    from   \
    (   \
    select mb_id,mb_11 from g5_member where (mb_last_check < (NOW() - INTERVAL  60 minute)) and    \
                                            (mb_problem_type = '계정좋아요정지')   \
                                         and mb_3>=current_date()+0    order by mb_last_check asc   \
    ) b   \
      \
    "
    
    total_count = curs.execute(sql)
    print("현재 작업중이지 않은 계정 총 %s개 남음" %(total_count))
    row = curs.fetchone()


     


      

    if row != None:
        print('a')
        _thread.start_new_thread(os_system,(autostart,))
        
    #subprocess.call('autostart.py',shell=True)
        #subprocess.call('autostart.py',shell=True)
        
        
        #ctypes.windll.shell32.ShellExecuteA(0,'autostart',autostart,None,None,1)    

        
    else:
        print("작업할 아이디 없음")
        # quit()

    time.sleep(30)
    
    #매일 새벽 4시에 팔로워리스트 날리기
    #curs.execute("delete FROM insta_follower_list where curtime() between 035900 and 040000 and run_time = 0")
    curs.execute("delete FROM insta_follower_list where curtime() between 035900 and 040000  ")
    
    curs.execute("delete FROM insta_follower_list where target_insta_id = '' ")
    

#실행창 이름은 팔로워플러스 아이디로...
ctypes.windll.kernel32.SetConsoleTitleW('main')




 
