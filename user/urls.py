# -*- coding: utf-8 -*-
# @time : 2024/9/19 15:30
# @author : 崔岚
# @file : urls.py
from django.urls import path, re_path
from .views import Interface

urlpatterns = [
    re_path(r'interface/(?P<path>.*)/$', Interface.as_view()),
]