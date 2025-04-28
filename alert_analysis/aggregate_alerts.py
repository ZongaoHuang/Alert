# aggregate_alerts.py
from LogEntry import LogEntry, AggregatedAlert
import hashlib


def create_alert_id(log_type, sip, dip, attack_type, earliest_time):
    # 创建一个唯一的标识符，基于五元组的哈希值
    id_string = f"{log_type}-{sip}-{dip}-{attack_type}-{earliest_time}"
    return hashlib.sha256(id_string.encode()).hexdigest()


def update_aggregated_alerts(aggregated_alerts, new_log_entries):
    for log_entry in new_log_entries:
        key = (log_entry.sip, log_entry.dip, log_entry.log_type, log_entry.attack_type)
        if key in aggregated_alerts:
            agg_alert = aggregated_alerts[key]
            if log_entry.timestamp > agg_alert.latest_time:
                agg_alert.latest_time = log_entry.timestamp
            agg_alert.ids.append(log_entry.id)
            agg_alert.num_alerts = len(agg_alert.ids)  # 更新num_alerts
        else:
            # 创建新的聚合告警
            new_ids = [log_entry.id]
            alert_id = create_alert_id(log_entry.log_type, log_entry.sip, log_entry.dip, log_entry.attack_type,
                                       log_entry.timestamp)
            aggregated_alerts[key] = AggregatedAlert(
                id=alert_id,
                log_type=log_entry.log_type,
                sip=log_entry.sip,
                dip=log_entry.dip,
                earliest_time=log_entry.timestamp,
                latest_time=log_entry.timestamp,
                attack_type=log_entry.attack_type,
                llm_score=0,
                entropy_score=0,
                rule_score=0,
                total_score=0,
                ids=new_ids,
            )
            aggregated_alerts[key].num_alerts = len(new_ids)  # 初始化num_alerts
