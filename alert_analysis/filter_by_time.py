from datetime import datetime


def time_deduplicate(data):
    # 按时间戳排序
    data.sort(key=lambda x: datetime.strptime(x.timestamp, "%Y-%m-%d %H:%M:%S"))
    filtered_data = []
    last_seen = {}
    # 读取每一条日志
    for item in data:
        try:
            # 以三元组作为键
            key = (item.sip, item.dip, item.attack_type, item.sport, item.dport)
            current_time = datetime.strptime(item.timestamp, "%Y-%m-%d %H:%M:%S")
            if key in last_seen:
                last_time = last_seen[key]
                # 如果时间差小于等于3秒，则忽略当前项
                if (current_time - last_time).total_seconds() <= 10:
                    item.filtered_stage = "时间窗口去重"
                    continue

            # 更新记录或添加新记录
            last_seen[key] = current_time
            filtered_data.append(item)
        except KeyError:
            # 如果找不到预期的键，跳过当前项
            continue

    return filtered_data
