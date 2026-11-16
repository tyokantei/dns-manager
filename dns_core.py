# coding=utf-8
"""
阿里云 DNS 解析操作库（面板后端版）
源自 Daniel 的 demo.py（原作者 @ThreeDays，2024/8/11），无第三方依赖。

与原脚本的差异（仅三处必要修正 + 一处安全升级，其余逻辑保持原样）：
1. search() 原来调用全局变量 dns.get(...)，只有作为脚本运行时才成立；
   作为库被 import 时会 NameError。改为 self.get(...)。
2. delete() 传 RecordId 时 else 分支里 data 未赋值就使用，会 NameError；
   改为直接构造待删列表。
3. get() 的 PageSize 默认值误判 PageNumber 是否为 None，已修正。
4. 接口地址由 http 改为 https://alidns.aliyuncs.com（签名与密钥不再走明文）。
原文件末尾示例注释中的密钥未带入本文件。
"""

import sys
import os
import io
from hashlib import sha1
from hmac import new as hmac
from uuid import uuid4
from base64 import b64encode
import json
from datetime import datetime
from urllib.parse import urlencode, quote_plus, quote
from urllib import request


class aliDns:
    __AccessKeyId = None
    __AccessSecret = None
    __params = None
    __DNS_URL = "https://alidns.aliyuncs.com"

    def __init__(self, AccessKeyId, AccessSecret):
        self.__AccessKeyId = AccessKeyId
        self.__AccessSecret = AccessSecret
        self.__params = {
            'SignatureType': '',
            'Format': 'JSON',
            'Version': '2015-01-09',
            'AccessKeyId': self.__AccessKeyId,
            'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': uuid4().int,
            'SignatureVersion': "1.0",
        }

    def __signature(self, data):
        data["Timestamp"] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        data["SignatureNonce"] = uuid4().int
        query = urlencode(sorted(data.items()))
        query = query.replace('+', '%20')
        sign = "GET" + "&" + quote_plus("/") + "&" + quote(query, safe='')
        sign = hmac((self.__AccessSecret + "&").encode('utf-8'), sign.encode('utf-8'), sha1).digest()
        sign = b64encode(sign).strip()
        data["Signature"] = sign
        return data

    def __merge_json(self, json1, json2):
        merged_json = json1.copy()
        for key, value in json2.items():
            if key in merged_json:
                if isinstance(merged_json[key], list) and isinstance(value, list):
                    merged_json[key].extend(value)
                elif isinstance(merged_json[key], dict) and isinstance(value, dict):
                    merged_json[key] = self.__merge_json(merged_json[key], value)
                else:
                    merged_json[key] = value
            else:
                merged_json[key] = value
        return merged_json

    def _call(self, data):
        data = {**self.__params, **data}
        data = self.__signature(data)
        url = f'{self.__DNS_URL}?{urlencode(data)}'
        req = request.Request(url)
        response = request.urlopen(req, timeout=15)
        html = response.read()
        return json.loads(html.decode('utf-8'))

    def get(self, DomainName, PageNumber=None, PageSize=None):
        """获取指定主域名某一页的解析记录列表。"""
        data = {
            'Action': 'DescribeDomainRecords',
            'DomainName': DomainName,
            'PageNumber': '1' if PageNumber is None else str(PageNumber),
            'PageSize': '20' if PageSize is None else str(PageSize)
        }
        try:
            return self._call(data)
        except Exception:
            return {"code": -1, "msg": "获取失败"}

    def get_all(self, DomainName):
        """拉取指定主域名的全部解析记录（自动翻页），返回记录 dict 列表。"""
        records = []
        page = 1
        while True:
            data = self.get(DomainName=DomainName, PageNumber=page, PageSize=100)
            if not isinstance(data, dict) or data.get("code") == -1:
                return {"code": -1, "msg": (data or {}).get("msg", "获取失败")}
            if "DomainRecords" not in data and data.get("Code"):
                return {"code": -1, "msg": data.get("Message") or data.get("Code")}
            batch = (data.get("DomainRecords") or {}).get("Record") or []
            records.extend(batch)
            total = data.get("TotalCount", len(records))
            if len(records) >= total or not batch:
                break
            page += 1
            if page > 50:
                break
        return {"code": 0, "records": records, "total": len(records)}

    def delete(self, RR, DomainName, Value=None, Type=None, Line=None, TTL=None, RecordId=None):
        """删除匹配的解析记录；传 RecordId 时只删该条。"""
        record = []
        if RecordId is None:
            data = self.search(RR=RR, DomainName=DomainName, Type=Type, Value=Value, Line=Line, TTL=TTL)
            targets = data["DomainRecords"]["Record"]
        else:
            targets = [{"RecordId": RecordId}]
        for item in targets:
            record.append(item)
            try:
                self._call({'Action': 'DeleteDomainRecord', 'RecordId': item["RecordId"]})
            except Exception:
                pass
        return {"msg": "delete", "record": record}

    def add(self, RR, DomainName, Type, Value, Line=None, TTL=None):
        """添加一条解析记录。"""
        data = {
            'Action': 'AddDomainRecord',
            'RR': RR,
            'DomainName': DomainName,
            'Type': Type,
            'Value': Value,
            'Line': "default" if Line is None else Line,
            'TTL': "600" if TTL is None else TTL,
        }
        try:
            return self._call(data)
        except Exception:
            return {"code": -1, "msg": "添加失败，记录已存在或参数错误。"}

    def search(self, DomainName, RR=None, Type=None, Value=None, Line=None, TTL=None, RecordId=None):
        """按条件检索解析记录（无条件时返回全部）。"""
        record = {}
        record["DomainRecords"] = {"Record": []}
        count = 1
        while True:
            data = self.get(DomainName=DomainName, PageNumber=count, PageSize=50)
            count += 1
            if count > 50:
                break
            if not isinstance(data, dict) or "DomainRecords" not in data:
                break
            if len(data["DomainRecords"]["Record"]) == 0:
                break
            record = self.__merge_json(record, data)
        if all(arg is None for arg in (RR, Type, Value, Line, TTL, RecordId)):
            return record

        while True:
            flag = True
            for item in record["DomainRecords"]["Record"]:
                if RR and RR != item["RR"]:
                    flag = False
                if Type and Type != item["Type"]:
                    flag = False
                if Value and Value != item["Value"]:
                    flag = False
                if Line and Line != item["Line"]:
                    flag = False
                if TTL and str(TTL) != str(item["TTL"]):
                    flag = False
                if RecordId and RecordId != item["RecordId"]:
                    flag = False
                if not flag:
                    record["DomainRecords"]["Record"].remove(item)
                    break
            if flag:
                break
        return record

    def getDnsRecordId(self, DomainName, RR, Type=None, Value=None, Line=None, TTL=None):
        """按条件查找解析记录的 RecordId 列表。"""
        RecordId = []
        data = self.search(DomainName=DomainName, RR=RR, Type=Type, Value=Value, Line=Line, TTL=TTL)
        for item in data["DomainRecords"]["Record"]:
            RecordId.append(item["RecordId"])
        return {"code": 0, "RecordIds": RecordId}

    def update(self, RecordId, DomainName, New_RR=None, New_Type=None, New_Value=None,
               New_Line=None, New_TTL=None, New_Status=None, New_Remark=None):
        """更新/修改指定 RecordId 的解析记录内容。"""
        data = self.search(DomainName=DomainName, RecordId=RecordId)["DomainRecords"]["Record"]
        if len(data) == 0:
            return {"code": -1, "msg": "对应RecordId记录不存在。"}
        data = data[0]
        RR = data["RR"]
        Type = data["Type"]
        Value = data["Value"]
        Line = data["Line"]
        TTL = data["TTL"]

        data = {
            'RecordId': RecordId,
            'Remark': New_Remark if New_Remark else "",
            'Status': New_Status if New_Status else "Enable",
        }
        data["RR"] = New_RR if New_RR else RR
        data["Type"] = New_Type if New_Type else Type
        data["Value"] = New_Value if New_Value else Value
        data["Line"] = New_Line if New_Line else Line
        data["TTL"] = New_TTL if New_TTL else TTL

        msg = ""
        code = 0
        if New_Remark:
            try:
                d = dict(data)
                d["Action"] = "UpdateDomainRecordRemark"
                d = self._call(d)
                msg += "更新备注==>RequestId：" + d["RequestId"]
            except Exception as e:
                code = -1
                msg += "更新备注失败！原因：" + str(e)
        if New_Status:
            try:
                d = dict(data)
                d["Action"] = "SetDomainRecordStatus"
                d = self._call(d)
                msg += f"，更新解析状态：{New_Status}==>RequestId：" + d["RequestId"]
            except Exception as e:
                code = -1
                msg += "，更新解析状态失败！原因：" + str(e)
        if (New_RR and New_RR != RR) or (New_Type and New_Type != Type) or \
           (New_Value and New_Value != Value) or (New_Line and New_Line != Line) or \
           (New_TTL and str(New_TTL) != str(TTL)):
            try:
                d = dict(data)
                d["Action"] = "UpdateDomainRecord"
                d = self._call(d)
                msg += f"，域名其他基本信息更新解析成功==>RequestId：" + d["RequestId"]
            except Exception as e:
                code = -1
                msg += "，域名其他基本信息更新解析失败！原因：" + str(e)
        else:
            msg += "，域名其他基本信息不需要更新（未发现更新值）"
        return {"code": code, "RecordId": RecordId, "msg": msg}
