#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
text = r"""
{
 "criticality": 10,
 "address": "http://192.168.220.134/",
 "target_id": "867656ea-ffc2-4849-b4e6-b7373a4d1e3d",
 "description": "xxxx"
}
"""
js = json.loads(text)
print js['target_id']