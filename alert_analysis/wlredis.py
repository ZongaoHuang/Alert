import redis
import time
from collections import deque
import json  # 导入 json 模块


class WhitelistManager:
    def __init__(self, host='localhost', port=6379, db=0):
        # 初始化 Redis 连接并设置白名单管理器。
        # decode_responses=False (默认) 确保 .get() 返回字节串，需手动解码
        self.redis = redis.StrictRedis(host=host, port=port, db=db)

    def add_to_whitelist(self, tuple_data, ttl_seconds):
        # 添加白名单，并设置指定的TTL，元组结构(log_type, sip, dip, sport, dport, attack_type)
        key = ':'.join(map(str, tuple_data))

        # 检测白名单项是否已存在
        # 注意：原逻辑是如果存在，仅更新TTL；如果不存在，则创建。
        if self.redis.exists(key):
            self.redis.expire(key, ttl_seconds)  # 刷新TTL
            return True  # 表示操作成功
        else:
            current_time = int(time.time())
            wl_data = {
                'creat_time': current_time,
                'hit_count': 0,
                'last_hit_time': None,
                'recent_alaert_ids': []
            }
            # 使用 json.dumps 将字典序列化为 JSON 字符串
            self.redis.setex(key, ttl_seconds, json.dumps(wl_data))
            return True  # 表示操作成功

    def is_in_whitelist(self, tuple_data, alert_ids=None):
        # 检查是否在白名单中，在则更新
        key = ':'.join(map(str, tuple_data))
        wl_data_bytes = self.redis.get(key)

        if wl_data_bytes:
            # 使用 json.loads 将字节串解码为 UTF-8 字符串后，再反序列化为 Python 字典
            wl_data = json.loads(wl_data_bytes.decode('utf-8'))

            # 更新白名单信息
            wl_data['hit_count'] += 1
            wl_data['last_hit_time'] = int(time.time())
            if alert_ids:
                alert_list_data = wl_data.get('recent_alaert_ids', [])
                if not isinstance(alert_list_data, list):  # 防御性检查
                    alert_list_data = []
                alert_list = deque(alert_list_data, maxlen=10)
                alert_list.append(alert_ids)
                wl_data['recent_alaert_ids'] = list(alert_list)

            # 将更新后的字典序列化回 JSON 字符串
            # 注意：SET 命令默认会移除 TTL。
            # 使用 keepttl=True (需要 Redis 6.0+) 来保留现有 TTL。
            # 如果 Redis 版本低于 6.0，或希望在命中时刷新 TTL，则需要其他策略（如 Lua 脚本或重新 SETEX）。
            # 此处假设我们希望保留 TTL。
            try:
                self.redis.set(key, json.dumps(wl_data), keepttl=True)
            except redis.exceptions.ResponseError:  # keepttl 可能不被旧版 Redis 支持
                # 对于旧版 Redis，这是一个非原子操作，可能导致 TTL 问题
                # 更稳健的方法是使用 Lua 脚本
                current_ttl = self.redis.ttl(key)
                self.redis.set(key, json.dumps(wl_data))
                if current_ttl and current_ttl > 0:
                    self.redis.expire(key, current_ttl)
            return True
        else:
            return False

    def get_whitelist_item(self, tuple_data):
        # 查询白名单中指定的条目内容。
        key = ':'.join(map(str, tuple_data))
        item_bytes = self.redis.get(key)
        if item_bytes:
            # 使用 json.loads 反序列化
            return json.loads(item_bytes.decode('utf-8'))
        return None

    def remove_from_whitelist(self, tuple_data):
        # 从 Redis 中删除指定的白名单条目。
        key = ':'.join(map(str, tuple_data))
        result = self.redis.delete(key)  # 尝试删除指定的键
        return result > 0  # 返回 True 如果删除了一个或多个条目

    def filter_by_whitelist(self, log_entries):
        # 根据白名单过滤日志条目。仅返回不在白名单中的条目。
        filtered_data = []
        for entry in log_entries:
            alert_ids = entry['ids']
            six_tuple = entry['info']

            if not self.is_in_whitelist(six_tuple, alert_ids):
                filtered_data.append(entry)

        return filtered_data

    def get_all_whitelist_items(self):
        """
        获取所有白名单条目 (使用 SCAN 命令)
        :return: 包含所有白名单项的字典
        """
        all_items = {}
        cursor = b'0'  # SCAN 的游标初始值为 '0' (字节串)
        while True:
            cursor, keys = self.redis.scan(cursor=cursor, match='*', count=100)  # count 是一个提示值
            for key_bytes in keys:
                value_bytes = self.redis.get(key_bytes)
                key_str = key_bytes.decode('utf-8')
                if value_bytes:
                    try:
                        # 使用 json.loads 反序列化
                        all_items[key_str] = json.loads(value_bytes.decode('utf-8'))
                    except json.JSONDecodeError:
                        # 处理非 JSON 数据或损坏的数据
                        all_items[key_str] = value_bytes.decode('utf-8', errors='replace')
            if cursor == b'0':  # 当游标返回 '0' 时，表示迭代完成
                break
        return all_items
