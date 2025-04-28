from LogEntry import SiptoNDipMapping

from LogEntry import SiptoNDipMapping, DiptoNSipMapping


def update_mappings(data, sip_to_dip_connections, dip_to_sip_connections):
    for item in data:
        sip = item.sip
        dip = item.dip
        attack_type = item.attack_type  # 从LogEntry对象获取攻击类型

        if sip not in sip_to_dip_connections:
            sip_to_dip_connections[sip] = SiptoNDipMapping(sip)
        sip_to_dip_connections[sip].add_dip(dip, item.id, attack_type)  # 传递攻击类型

        if dip not in dip_to_sip_connections:
            dip_to_sip_connections[dip] = DiptoNSipMapping(dip)
        dip_to_sip_connections[dip].add_sip(sip, item.id, attack_type)  # 传递攻击类型

    return sip_to_dip_connections, dip_to_sip_connections




def filter_one_to_many(sip_to_dip_connections):
    # 过滤一对多的情况
    one_to_many_mappings = []

    for sip, mapping in sip_to_dip_connections.items():
        # 如果一个sip对应多个不同的dip，视为一对多
        if len(mapping.dips) > 1:
            one_to_many_mappings.append(mapping)  # 收集所有符合多对一条件的结构体

    # 返回一对多的日志ID列表
    return one_to_many_mappings


def filter_many_to_one(dip_to_sip_connections):
    # 过滤多对一的情况
    many_to_one_mappings = []

    for dip, mapping in dip_to_sip_connections.items():
        # 如果一个dip对应多个不同的sip，视为多对一
        if len(mapping.sips) > 1:
            many_to_one_mappings.append(mapping)  # 收集所有符合多对一条件的结构体

    # 返回多对一的日志ID列表
    return many_to_one_mappings


def filter_one_to_one(sip_to_dip_connections, dip_to_sip_connections):
    one_to_one_mappings = []

    # 遍历sip到dip的映射
    for sip, sip_mapping in sip_to_dip_connections.items():
        if len(sip_mapping.dips) == 1:  # 确保这个sip只对应一个dip
            # 获取这个唯一的dip
            only_dip = list(sip_mapping.dips.keys())[0]
            # 检查这个dip是否只对应这个sip
            if len(dip_to_sip_connections[only_dip].sips) == 1 and sip in dip_to_sip_connections[only_dip].sips:
                # 如果是真正的一对一关系，添加整个SiptoNDipMapping结构体
                one_to_one_mappings.append(sip_mapping)

    # 返回一对一的结构体列表
    return one_to_one_mappings

