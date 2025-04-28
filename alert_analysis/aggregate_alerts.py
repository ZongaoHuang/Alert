# aggregate_alerts.py
from LogEntry import LogEntry, AggregatedAlert
import hashlib
from collections import defaultdict


def create_alert_id(log_type, sip, dip, attack_type, earliest_time):
    # 创建一个唯一的标识符，基于五元组的哈希值
    id_string = f"{log_type}-{sip}-{dip}-{attack_type}-{earliest_time}"
    return hashlib.sha256(id_string.encode()).hexdigest()


def update_mappings(log_entries):
    """
    构建源IP到目的IP和目的IP到源IP的映射关系.
    Args:
        log_entries: 原始日志条目列表 (List[LogEntry]).
    Returns:
        tuple: 包含两个字典:
            - sip_to_dip_map (dict): {sip: {dip: [LogEntry, ...], ...}, ...}
            - dip_to_sip_map (dict): {dip: {sip: [LogEntry, ...], ...}, ...}
    """
    # 使用 defaultdict 简化代码
    # sip_to_dip_map: key=sip, value=dict(key=dip, value=list of LogEntry)
    sip_to_dip_map = defaultdict(lambda: defaultdict(list))
    # dip_to_sip_map: key=dip, value=dict(key=sip, value=list of LogEntry)
    dip_to_sip_map = defaultdict(lambda: defaultdict(list))

    for log in log_entries:
        sip = log.sip
        dip = log.dip
        # 更新 sip -> dip 映射
        sip_to_dip_map[sip][dip].append(log)
        # 更新 dip -> sip 映射
        dip_to_sip_map[dip][sip].append(log)

    # 将 defaultdict 转换回普通 dict (可选, 但更清晰)
    sip_to_dip_map_final = {sip: dict(dips) for sip, dips in sip_to_dip_map.items()}
    dip_to_sip_map_final = {dip: dict(sips) for dip, sips in dip_to_sip_map.items()}

    return sip_to_dip_map_final, dip_to_sip_map_final

def filter_one_to_many(sip_to_dip_map):
    """
    从 SIP -> DIP 映射中筛选出一对多攻击模式 (一个源IP攻击多个目的IP).
    Args:
        sip_to_dip_map (dict): {sip: {dip: [LogEntry, ...], ...}, ...}
    Returns:
        dict: 包含一对多映射的字典 {sip: {dip: [LogEntry, ...], ...}, ...}
    """
    one_to_many_mappings = {}
    for sip, dip_map in sip_to_dip_map.items():
        # 如果一个源IP连接了超过一个目的IP，则认为是一对多
        if len(dip_map) > 1:
            one_to_many_mappings[sip] = dip_map
    return one_to_many_mappings

def filter_many_to_one(dip_to_sip_map):
    """
    从 DIP -> SIP 映射中筛选出多对一攻击模式 (多个源IP攻击一个目的IP).
    Args:
        dip_to_sip_map (dict): {dip: {sip: [LogEntry, ...], ...}, ...}
    Returns:
        dict: 包含多对一映射的字典 {dip: {sip: [LogEntry, ...], ...}, ...}
    """
    many_to_one_mappings = {}
    for dip, sip_map in dip_to_sip_map.items():
        # 如果一个目的IP被超过一个源IP连接，则认为是多对一
        if len(sip_map) > 1:
            many_to_one_mappings[dip] = sip_map
    return many_to_one_mappings

def filter_one_to_one(sip_to_dip_map, dip_to_sip_map):
    """
    筛选出严格的一对一攻击模式 (一个源IP只攻击一个目的IP，且该目的IP只被该源IP攻击).
    Args:
        sip_to_dip_map (dict): {sip: {dip: [LogEntry, ...], ...}, ...}
        dip_to_sip_map (dict): {dip: {sip: [LogEntry, ...], ...}, ...}
    Returns:
        dict: 包含一对一映射的字典 {sip: {dip: [LogEntry, ...]}, ...}
    """
    one_to_one_mappings = {}
    for sip, dip_map in sip_to_dip_map.items():
        # 源IP只连接一个目的IP
        if len(dip_map) == 1:
            dip = list(dip_map.keys())[0]  # 获取唯一的目的IP
            # 检查该目的IP是否也只连接了这一个源IP
            if dip in dip_to_sip_map and len(dip_to_sip_map[dip]) == 1:
                # 确保dip_to_sip_map[dip]中的唯一sip就是当前的sip
                # (这一步是隐式保证的，因为如果dip连接了其他sip，len会大于1)
                one_to_one_mappings[sip] = dip_map # dip_map 已经是 {dip: [LogEntry, ...]}
    return one_to_one_mappings

def create_aggregated_alerts(one_to_many_mappings, many_to_one_mappings, one_to_one_mappings):
    """
    从不同类型的IP映射创建聚合告警对象
    Args:
        one_to_many_mappings (dict): 一对多映射 {sip: {dip: [LogEntry, ...], ...}, ...}
        many_to_one_mappings (dict): 多对一映射 {dip: {sip: [LogEntry, ...], ...}, ...}
        one_to_one_mappings (dict): 一对一映射 {sip: {dip: [LogEntry, ...]}, ...}
    Returns:
        list: AggregatedAlert对象列表
    """
    aggregated_alerts = []
    
    # 处理一对多映射 (一个源IP攻击多个目的IP)
    for sip, dip_map in one_to_many_mappings.items():
        all_logs = []
        for log_list in dip_map.values():
            all_logs.extend(log_list)
        
        if not all_logs:
            continue
            
        log_type = all_logs[0].log_type
        attack_type = "one_to_many"
        earliest_time = min(log.timestamp for log in all_logs)
        latest_time = max(log.timestamp for log in all_logs)
        
        alert_id = create_alert_id(log_type, sip, "multiple", attack_type, earliest_time)
        
        alert = AggregatedAlert(
            alert_id=alert_id,
            log_type=log_type,
            sip=sip,
            dip="multiple",
            attack_type=attack_type,
            earliest_time=earliest_time,
            latest_time=latest_time,
            count=len(all_logs),
            unique_dips=list(dip_map.keys()),
            unique_sips=[sip],
            log_entries=all_logs
        )
        aggregated_alerts.append(alert)
    
    # 处理多对一映射 (多个源IP攻击一个目的IP)
    for dip, sip_map in many_to_one_mappings.items():
        all_logs = []
        for log_list in sip_map.values():
            all_logs.extend(log_list)
            
        if not all_logs:
            continue
            
        log_type = all_logs[0].log_type
        attack_type = "many_to_one"
        earliest_time = min(log.timestamp for log in all_logs)
        latest_time = max(log.timestamp for log in all_logs)
        
        alert_id = create_alert_id(log_type, "multiple", dip, attack_type, earliest_time)
        
        alert = AggregatedAlert(
            alert_id=alert_id,
            log_type=log_type,
            sip="multiple",
            dip=dip,
            attack_type=attack_type,
            earliest_time=earliest_time,
            latest_time=latest_time,
            count=len(all_logs),
            unique_dips=[dip],
            unique_sips=list(sip_map.keys()),
            log_entries=all_logs
        )
        aggregated_alerts.append(alert)
    
    # 处理一对一映射 (一个源IP只攻击一个目的IP)
    for sip, dip_map in one_to_one_mappings.items():
        dip = list(dip_map.keys())[0]
        logs = dip_map[dip]
        
        if not logs:
            continue
            
        log_type = logs[0].log_type
        # 使用第一条日志的攻击类型或默认值
        attack_type = getattr(logs[0], 'attack_type', "one_to_one")
            
        earliest_time = min(log.timestamp for log in logs)
        latest_time = max(log.timestamp for log in logs)
        
        alert_id = create_alert_id(log_type, sip, dip, attack_type, earliest_time)
        
        alert = AggregatedAlert(
            alert_id=alert_id,
            log_type=log_type,
            sip=sip,
            dip=dip,
            attack_type=attack_type,
            earliest_time=earliest_time,
            latest_time=latest_time,
            count=len(logs),
            unique_dips=[dip],
            unique_sips=[sip],
            log_entries=logs
        )
        aggregated_alerts.append(alert)
    
    return aggregated_alerts

def aggregate_alerts(log_entries):
    """
    分析日志条目并生成聚合告警对象
    Args:
        log_entries: 原始日志条目列表 (List[LogEntry])
    Returns:
        list: AggregatedAlert对象列表
    """
    # 构建IP映射关系
    sip_map, dip_map = update_mappings(log_entries)
    
    # 筛选出不同的攻击模式
    one_to_many = filter_one_to_many(sip_map)
    many_to_one = filter_many_to_one(dip_map)
    one_to_one = filter_one_to_one(sip_map, dip_map)
    
    # 创建聚合告警
    return create_aggregated_alerts(one_to_many, many_to_one, one_to_one)
