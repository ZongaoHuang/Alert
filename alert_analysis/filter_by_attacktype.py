
def filter_by_attack_type(data, type_filters):
    # 创建一个新的列表存储过滤后的日志条目
    filtered_data = []
    # 遍历每个日志条目
    for item in data:
        # 获取当前日志条目的类型
        current_type = item.log_type
        # 检查是否为当前日志类型设置了过滤规则
        if current_type in type_filters:
            # 如果当前条目的攻击类型不在当前日志类型的过滤列表中，则添加到新的列表中
            if item.attack_type not in type_filters[current_type]:
                filtered_data.append(item)
        else:
            # 如果没有为当前日志类型设置过滤规则，则所有条目均添加
            filtered_data.append(item)

    return filtered_data
