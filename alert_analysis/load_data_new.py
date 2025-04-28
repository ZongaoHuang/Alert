import json
import re
from LogEntry import LogEntry


def read_log_file(file_path, log_entries):
    # 打开并读取JSON文件
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    patterns = [
        re.compile(r'tianyan-.*'),
        re.compile(r'alarm-tianyan-.*'),
        re.compile(r'zhongzi-.*'),
        re.compile(r'v2zhongzi-*'),
        re.compile(r'waf-*')
    ]
    for entry_type, entries in data.items():
        if entry_type == "tianyan":
            for entry in entries:
                source = entry['_source']
                if 'sip' not in source or 'dip' not in source or 'rule_name' not in source:
                    continue  # 如果任一关键字段缺失，跳过此日志条目
                entry = LogEntry(
                    log_type="tianyan",  # 日志类型
                    id=entry.get('_id'),  # 日志index
                    sip=source.get('sip', 'Null'),  # 源IP
                    dip=source.get('dip', 'Null'),  # 目的IP
                    sport=source.get('sport', 'Null'),  # 源端口
                    dport=source.get('dport', 'Null'),  # 目的端口
                    timestamp=source.get('@timestamp', 'Null'),  # 时间戳
                    attack_type=source.get('rule_name', 'Null'),  # 攻击类型
                    attack_result=source.get('attack_result', 'Null'),  # 攻击结果
                    severity=source.get('severity', 'Null'),  # 告警级别
                    req_header=source.get('req_header', 'Null'),  # 请求头
                    req_body=source.get('req_body', 'Null'),  # 请求体
                    rsp_header=source.get('rsp_header', 'Null'),  # 响应头
                    rsp_body=source.get('rsp_body', 'Null'),  # 响应体
                    packet_data=source.get('packet_data', 'Null'),  # 数据流
                    threat_status=0,  # 是否为威胁日志
                    filtered_stage="",  # 在哪一阶段被筛选掉
                    related_alerts_ids=[],  # 告警关联
                )
                log_entries.append(entry)  # 将对象添加到列表中
        elif entry_type == "alarm-tianyan":
            for entry in entries:
                source = entry['_source']
                if 'sip' not in source or 'dip' not in source or 'vuln_type' not in source:
                    continue  # 如果任一关键字段缺失，跳过此日志条目
                entry = LogEntry(
                    log_type="alarm-tianyan",  # 日志类型
                    id=entry.get('_id'),  # 日志index
                    sip=source.get('sip'),  # 源IP
                    dip=source.get('dip'),  # 目的IP
                    sport=source.get('sport', 'Null'),  # 源端口
                    dport=source.get('dport', 'Null'),  # 目的端口
                    timestamp=source.get('@timestamp', 'Null'),  # 时间戳
                    attack_type=source.get('vuln_type', 'Null'),  # 攻击类型
                    attack_result=source.get('host_state', 'Null'),  # 攻击结果
                    severity=source.get('hazard_level', 'Null'),  # 告警级别
                    req_header=source.get('payload', {}).get('req_header', 'Null'),  # 请求头
                    req_body=source.get('payload', {}).get('req_body', 'Null'),  # 请求体
                    rsp_header=source.get('payload', {}).get('rsp_header', 'Null'),  # 响应头
                    rsp_body=source.get('payload', {}).get('rsp_body', 'Null'),  # 响应体
                    packet_data=source.get('payload', {}).get('packet_data', 'Null'),  # 数据流
                    threat_status=0,  # 是否为威胁日志
                    filtered_stage="",  # 在哪一阶段被筛选掉
                    related_alerts_ids=[],  # 告警关联
                )
                log_entries.append(entry)  # 将对象添加到列表中
        elif entry_type == "zhongzi":
            for entry in entries:
                source = entry['_source']
                if 'sip' not in source or 'dip' not in source or 'event_name' not in source:
                    continue  # 如果任一关键字段缺失，跳过此日志条目
                entry = LogEntry(
                    log_type="zhongzi",  # 日志类型
                    id=entry.get('_id'),  # 日志index
                    sip=source.get('sip'),  # 源IP
                    dip=source.get('dip'),  # 目的IP
                    sport=source.get('sport', 'Null'),  # 源端口
                    dport=source.get('dport', 'Null'),  # 目的端口
                    timestamp=source.get('@timestamp', 'Null'),  # 时间戳
                    attack_type=source.get('event_name', 'Null'),  # 攻击类型
                    attack_result=source.get('event_result', 'Null'),  # 攻击结果
                    severity=source.get('event_severity', 'Null'),  # 告警级别
                    req_header='Null',
                    req_body='Null',
                    rsp_header='Null',
                    rsp_body='Null',
                    packet_data=source.get('payload', 'Null'),  # 数据流
                    threat_status=0,  # 是否为威胁日志
                    filtered_stage="",  # 在哪一阶段被筛选掉
                    related_alerts_ids=[],  # 告警关联
                )
                log_entries.append(entry)  # 将对象添加到列表中
        elif entry_type == "v2zhongzi":
            for entry in entries:
                source = entry['_source']
                if 'sip' not in source or 'dip' not in source or 'msg' not in source:
                    continue  # 如果任一关键字段缺失，跳过此日志条目
                attack_type = source.get('msg', 'Null')
                if attack_type.startswith('会话黑名单'):
                    attack_type = '会话黑名单'
                entry = LogEntry(
                    log_type="v2zhongzi",  # 日志类型
                    id=entry.get('_id'),  # 日志index
                    sip=source.get('sip'),  # 源IP
                    dip=source.get('dip'),  # 目的IP
                    sport=source.get('sport', 'Null'),  # 源端口
                    dport=source.get('dport', 'Null'),  # 目的端口
                    timestamp=source.get('@timestamp', 'Null'),  # 时间戳
                    attack_type=attack_type,  # 攻击类型
                    attack_result=source.get('result', 'Null'),  # 攻击结果
                    severity=source.get('level', 'Null'),  # 告警级别
                    req_header=source.get('req_header', 'Null'),
                    req_body=source.get('req_body', 'Null'),
                    rsp_header=source.get('rsp_header', 'Null'),
                    rsp_body=source.get('rsp_body', 'Null'),
                    packet_data=source.get('fingerprint', 'Null'),  # 数据流
                    threat_status=0,  # 是否为威胁日志
                    filtered_stage="",  # 在哪一阶段被筛选掉
                    related_alerts_ids=[],  # 告警关联
                )
                log_entries.append(entry)  # 将对象添加到列表中
        elif entry_type == "waf":
            for entry in entries:
                source = entry['_source']
                if 'sip' not in source or 'dip' not in source or 'attack_type' not in source:
                    continue  # 如果任一关键字段缺失，跳过此日志条目
                # 处理攻击类型
                attack_types = source.get('attack_type', [])
                if isinstance(attack_types, list):
                    if "Inject" in attack_types:
                        inject_attack_types = source.get('inject_attack_type', [])
                        attack_type = '_'.join(inject_attack_types) if isinstance(inject_attack_types,
                                                                                      list) else inject_attack_types
                    else:
                        attack_type = '_'.join(attack_types)
                else:
                    attack_type = attack_types  # 如果不是列表，直接使用值

                entry = LogEntry(
                    log_type="waf",  # 日志类型
                    id=entry.get('_id'),  # 日志index
                    sip=source.get('src_ip'),  # 源IP
                    dip=source.get('dst_ip'),  # 目的IP
                    sport=source.get('src_port', 'Null'),  # 源端口
                    dport=source.get('dst_port', 'Null'),  # 目的端口
                    timestamp=source.get('@timestamp', 'Null'),  # 时间戳
                    attack_type=attack_type,  # 攻击类型
                    attack_result=source.get('status', 'Null'),  # 攻击结果
                    severity=source.get('protect_level', 'Null'),  # 告警级别
                    req_header=source.get('api_snap_reqheader', 'Null'),
                    req_body=source.get('req_body', 'Null'),
                    rsp_header=source.get('api_snap_respheader', 'Null'),
                    rsp_body=source.get('rsp_body', 'Null'),
                    packet_data=source.get('inject_payload', 'Null'),  # 数据流
                    threat_status=0,  # 是否为威胁日志
                    filtered_stage="",  # 在哪一阶段被筛选掉
                    related_alerts_ids=[],  # 告警关联
                )
                log_entries.append(entry)  # 将对象添加到列表中


