from elasticsearch import Elasticsearch
from datetime import datetime
from multiprocessing import Queue
import elasticsearch
import tomli
import time
import ujson
import json
import sys
import gc


# 读取上次查询的最大时间戳
def read_last_timestamp(logs_type, default_time, filename='last_timestamp.json'):
    try:
        with open(filename, 'r') as file:
            last_timestamp = json.load(file)

        # 如果没有上次的时间戳，使用默认的时间
        for logs_name in logs_type:
            if logs_name not in last_timestamp.keys():
                last_timestamp[logs_name] = default_time
                # last_timestamp[logs_name] = (
                #     (datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'))

        return last_timestamp

    except:
        # 使用默认的时间
        last_timestamp = {}
        for logs_name in logs_type:
            last_timestamp[logs_name] = default_time
            # last_timestamp[logs_name] = (
            #     (datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'))

        return last_timestamp


# 保存当前查询的最大时间戳
def save_last_timestamp(logs_type, update_timestamp, latest_timestamp, filename='last_timestamp.json'):
    try:
        with open(filename, 'r') as file:
            timestamp = json.load(file)

        timestamp.update(latest_timestamp)

        if update_timestamp:
            # 删除已经取消获取的日志时间戳
            timestamp = {k: v for k, v in timestamp.items() if k in logs_type}

        with open(filename, 'w') as file:
            json.dump(timestamp, file)

    except:
        with open(filename, 'w') as file:
            json.dump(latest_timestamp, file)


def get_data(es, index_name, query_body):
    try:
        response = es.search(
            index=index_name,
            body=query_body,
            scroll='2m',
        )

        hits = response['hits']['hits']
        # 查询无果
        if len(hits) == 0:
            return hits

        scroll_id = response['_scroll_id']

        while len(response['hits']['hits']):
            response = es.scroll(
                scroll_id=scroll_id,
                scroll='2m'
            )
            hits.extend(response['hits']['hits'])

        return hits

    except elasticsearch.NotFoundError:
        print('elasticsearch NotFoundError...')
        return []

    except elasticsearch.ConnectionTimeout:
        print('elasticsearch ConnectionTimeout...')
        return []


# 获取 Elasticsearch 日志
def get_logs_data(es, logs_name, since_timestamp):
    query_body = {
        "_source": {
            "excludes": ["message"]
        },
        "query": {
            "range": {
                "@timestamp": {
                    "gt": since_timestamp,      # 查询大于上次时间戳的所有日志
                    "format": "yyyy-MM-dd HH:mm:ss"
                }
            }
        },
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "size": 10000
    }

    index_name = logs_name + "-*"
    hits = get_data(es, index_name, query_body)

    # current_date = datetime.now()
    #
    # # 检测下一天日志是否更新
    # index_date = current_date + timedelta(days=1)
    # index_name = f"{logs_name}-{index_date.strftime('%Y.%m.%d')}"
    # nextday_hits = get_data(index_name, query_body)
    #
    # if nextday_hits is False:
    #     # 下一天日志未更新，获取当天日志
    #     index_date = current_date
    #     index_name = f"{logs_name}-{index_date.strftime('%Y.%m.%d')}"
    #     hits = get_data(index_name, query_body)
    #
    #     if hits is False:
    #         hits = []
    #     return hits
    #
    # # 下一天日志已更新，查询当天日志是否有更新
    # index_date = current_date
    # index_name = f"{logs_name}-{index_date.strftime('%Y.%m.%d')}"
    # hits = get_data(index_name, query_body)
    #
    # if hits is False:
    #     hits = []
    #
    # hits.extend(nextday_hits)

    return hits


# 将日志保存到文件
def save_logs_to_file(logs):
    # 以当前时间作为文件名
    filename = datetime.now().strftime("%Y%m%d%H%M%S")
    with open(f'./logs/{filename}.json', 'w') as file:
        ujson.dump(logs, file)

    return filename


def read_toml(path):
    with open(path, mode="rb") as fp:
        data = tomli.load(fp)
    return data['update_timestamp'], data["logs_type"], data["default_time"], data['waiting_time']


def get_logs(queue):
    # 连接 Elasticsearch 客户端
    es = Elasticsearch(...)

    # 初始化
    toml_path = "./get_logs.toml"
    latest_timestamp = {}   # 用于储存本次获取每类日志最近时间戳

    # 主循环
    try:
        while True:
            # 初始化
            all_logs_data = {}
            update_timestamp, logs_type, default_time, waiting_time = read_toml(toml_path)
            print("------------------------------------------------------------")

            # 获取日志获取时间戳
            # last_timestamp = latest_timestamp.copy()
            last_timestamp = read_last_timestamp(logs_type, default_time)
            latest_timestamp = last_timestamp.copy()

            # 获取日志
            for logs_name in logs_type:
                # 当出现新日志类型时，查询从配置文件的默认时间开始
                # if logs_name not in last_timestamp.keys():
                #     last_timestamp[logs_name] = default_time
                #     latest_timestamp[logs_name] = default_time
                logs_data = get_logs_data(es, logs_name, last_timestamp[logs_name])

                if len(logs_data):
                    # # 时间戳排序
                    # logs_data = sorted(logs_data, key=lambda x: datetime.
                    #                    strptime(x['_source']['@timestamp'], '%Y-%m-%d %H:%M:%S'))

                    # 将日志保存
                    all_logs_data[logs_name] = logs_data

                    # 更新最大时间戳
                    latest_timestamp[logs_name] = logs_data[-1]['_source']['@timestamp']                       

                print(f'{logs_name:<15}: {last_timestamp[logs_name]} - {latest_timestamp[logs_name]}, count: {len(logs_data)}')

                # 显式释放内存
                del logs_data
                gc.collect()

            # 保存本批次日志最晚时间戳
            save_last_timestamp(logs_type, update_timestamp, latest_timestamp)

            # 保存日志到文件
            filename = save_logs_to_file(all_logs_data)
            print(f'logs in file [{filename}.json] ...')
            
            # 将文件名称送入队列
            queue.put(filename)

            # 等待
            print("\nwait...\n")
            time.sleep(waiting_time)
    except KeyboardInterrupt:
        print("日志获取程序已中断")


if __name__ == '__main__':
    queue = Queue()
    get_logs(queue)
