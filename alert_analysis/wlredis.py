import redis
import time
from collections import deque


class WhitelistManager:
    def __init__(self, host='localhost', port=6379, db=0):
        # 初始化 Redis 连接并设置白名单管理器。
        self.redis = redis.StrictRedis(host=host, port=port, db=db)

    def add_to_whitelist(self, tuple_data, ttl_seconds):
        # 添加白名单，并设置指定的TTL，元组结构(log_type, sip, dip, sport, dport, attack_type)
        key = ':'.join(map(str, tuple_data))

        # 检测白名单项是否已存在
        item = self.redis.get(key)
        if item:
            self.redis.expire(key, ttl_seconds)
            return
        else:
            current_time = int(time.time())

            wl_data = {
                'creat_time': current_time,
                'hit_count': 0,
                'last_hit_time': None,
                'recent_alaert_ids': []
            }

            self.redis.setex(key, ttl_seconds, str(wl_data))
            return

    def is_in_whitelist(self, tuple_data, alert_ids=None):
        # 检查是否在白名单中，在则更新
        key = ':'.join(map(str, tuple_data))
        wl_data = self.redis.get(key)

        if wl_data:
            wl_data = eval(wl_data.decode('utf-8'))

            # 更新白名单信息
            wl_data['hit_count'] += 1
            wl_data['last_hit_time'] = int(time.time())
            if alert_ids:
                alert_list = deque(wl_data.get('recent_alaert_ids', []), maxlen=10)
                alert_list.append(alert_ids)
                wl_data['recent_alaert_ids'] = list(alert_list)

            self.redis.set(key, str(wl_data))
            return True
        else:
            return False

    def get_whitelist_item(self, tuple_data):
        # 查询白名单中指定的条目内容。
        key = ':'.join(map(str, tuple_data))
        item = self.redis.get(key)
        return item.decode('utf-8') if item else None  # 返回找到的内容或 None

    def remove_from_whitelist(self, tuple_data):
        # 从 Redis 中删除指定的白名单条目。
        key = ':'.join(map(str, tuple_data))
        result = self.redis.delete(key)  # 尝试删除指定的键
        return result > 0  # 返回 True 如果删除了一个或多个条目

    def filter_by_whitelist(self, log_entries):
        # 根据白名单过滤日志条目。仅返回不在白名单中的条目。
        filtered_data = []
        for entry in log_entries:
            # six_tuple = (
            #     entry.log_type,
            #     entry.sip,
            #     entry.dip,
            #     entry.sport,
            #     entry.dport,
            #     entry.attack_type
            # )
            alert_ids = entry['ids']
            six_tuple = entry['info']

            if not self.is_in_whitelist(six_tuple, alert_ids):
                filtered_data.append(entry)
            # else:
            #     print(f"白名单条目：{entry}")

        return filtered_data

    def get_all_whitelist_items(self):
        """
        获取所有白名单条目
        :return: 包含所有白名单项的字典
        """
        keys = self.redis.keys('*')  # 获取所有键
        all_items = {}
        for key in keys:
            value = self.redis.get(key)
            all_items[key.decode('utf-8')] = value.decode('utf-8') if value else None
        return all_items
