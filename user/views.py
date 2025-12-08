import datetime
import hashlib
import json
import time

from django.shortcuts import render
from django.http.response import JsonResponse, HttpResponse
from django.contrib.auth.models import User, Permission, Group
from django.views.decorators.gzip import gzip_page
from django.core.paginator import Paginator
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.views import APIView


class GetSign:

    # 读取token文件
    def readToken(self):
        # with open('static/datas_key.json', 'r') as f:
        #     txt = f.read()
        # items = json.loads(txt)
        return {
            "xxx": {
                "Token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "expires": "2030-12-29 12:00:00"
            }
        }

    # 验证签名
    def getSign(self, appkey, timestamp, sign):
        if not appkey:
            return {'code': 1, 'success': False, "msg": 'Appkey is empty'}
        if not timestamp:
            return {'code': 1, 'success': False, "msg": 'TimeStamp is empty'}
        if not sign:
            return {'code': 1, 'success': False, "msg": 'sign is empty'}
        items = self.readToken()['data']
        for item in items:
            if appkey == item['Appkey']:
                expires = datetime.datetime.strptime(item['expires'], '%Y-%m-%d %H:%M:%S')
                if expires < datetime.datetime.now():
                    return {"code": 1, 'success': False, "msg": "Appkey is expires"}
                elif (int(timestamp) + 120) < int(time.time()) or (int(timestamp) - 120) > int(time.time()):
                    return {"code": 1, 'success': False, "msg": "TimeStamp is expires"}
                else:
                    plaintext = appkey + item['Token'] + str(timestamp)
                    h1 = hashlib.md5()
                    h2 = hashlib.md5()
                    h1.update(plaintext.encode('utf-8'))
                    h2.update(h1.hexdigest().encode('utf-8'))
                    newsign = h2.hexdigest()
                    if sign == newsign:
                        return {"code": 0, "msg": newsign}
                    return {'code': 1, 'success': False, "msg": '验签失败'}
        return {"code": 1, 'success': False, "msg": "Appkey does not exist"}


class Interface(APIView):
    def post(self, request, path):
        try:
            data = json.loads(request.body)
            getSign = GetSign()
            appkey = data.get('Appkey', '')
            timestamp = data.get('timestamp', '')
            sign = data.get('sign', '')
            item = getSign.getSign(appkey, timestamp, sign)
            if item['code'] == 1:
                return JsonResponse({'code': 1, 'success': False, "msg": item['msg']})
            action = data.get('action')
            if path == 'user':
                from django.contrib.auth.models import User, Permission, Group
                if action == 'user_add':
                    ret = {
                        'first_name': data['name'],
                        'username': data['username'],
                        'password':  data['password'],
                        'is_active': True
                    }
                    User.objects.create(**ret)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'user_del':
                    username = data['username']
                    User.objects.filter(username=username).delete()
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'user_on_off':
                    username = data['username']
                    User.objects.filter(username=username).update(is_active=data['is_active'])
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'user_reset_password':
                    username = data['username']
                    password = data['password']
                    User.objects.filter(username=username).update(password=password)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'user_add_perm':
                    username = data['username']
                    user = User.objects.get(username=username)
                    add_perm = data['add_perm']
                    del_perm = data['del_perm']
                    if add_perm:
                        add_perms = [Permission.objects.filter(codename=key)[0] for key in add_perm]
                        user.user_permissions.add(*add_perms)  # 添加权限
                    if del_perm:
                        del_perms = [Permission.objects.filter(codename=key)[0] for key in del_perm]
                        user.user_permissions.remove(*del_perms)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'user_add_group':
                    username = data['username']
                    user = User.objects.get(username=username)
                    add_groups = data['add_groups']
                    del_groups = data['del_groups']
                    if add_groups:
                        add_groups = [Group.objects.filter(name=key)[0] for key in add_groups]
                        user.groups.add(*add_groups)
                    if del_groups:
                        del_groups = [Group.objects.filter(name=key)[0] for key in del_groups]
                        user.groups.remove(*del_groups)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'group_add':
                    group_name = data['group_name']
                    try:
                        Group.objects.create(name=group_name)
                    except:
                        return JsonResponse({'code': 1, "msg": "已存在相同的分组"})
                    return JsonResponse({'code': 0, "msg": "success"})
                elif action == 'group_del':
                    group_name = data['group_name']
                    Group.objects.filter(name=group_name).delete()
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'group_edit_perm':
                    group_name = data['group_name']
                    group = Group.objects.get(name=group_name)
                    add_perm = data['add_perm']
                    del_perm = data['del_perm']
                    if add_perm:
                        add_perms = [Permission.objects.filter(codename=key)[0] for key in add_perm]
                        group.permissions.add(*add_perms)  # 添加权限
                    if del_perm:
                        del_perms = [Permission.objects.filter(codename=key)[0] for key in del_perm]
                        group.permissions.remove(*del_perms)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'change_password':
                    user_id = data['user_id']
                    password = data['password']
                    User.objects.filter(id=user_id).update(password=password)
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'perm_add':
                    ret = {
                        'name': data['name'],
                        'codename': data['codename'],
                        'content_type_id': 1
                    }
                    try:
                        Permission.objects.create(**ret)
                        return JsonResponse({'code': 0, "msg": "success"})
                    except:
                        return JsonResponse({'code': 1, "msg": "已存在相同的权限"})
                elif action == 'perm_del':
                    codename = data['codename']
                    Permission.objects.filter(codename=codename).delete()
                    return JsonResponse({"code": 0, "msg": "success"})
                elif action == 'perm_edit':
                    ret = {
                        'name': data['name'],
                        'codename': data['codename'],
                        'content_type_id': 1
                    }
                    Permission.objects.filter(codename=data['codename']).update(**ret)
                    return JsonResponse({"code": 0, "msg": "success"})

            return JsonResponse({'code': 404}, status=404)
        except Exception as e:
            return JsonResponse({'code': 500, 'msg': f'{e.__traceback__.tb_lineno} {e}'})

    def get(self, request, path):
        return JsonResponse({'code': 404}, status=404)