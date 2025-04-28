from load_data_new import read_log_file
from filter_by_time import time_deduplicate
from filter_by_attacktype import filter_by_attack_type
from save_to_json import log_entry_to_dict
from whitelist import filter_by_whitelist
from filter_by_sipdip import *
from aggregate_alerts import update_aggregated_alerts
from datetime import datetime,timedelta
import elasticsearch
import requests
import time
import json
import sys
import os
import re


# 获取上一日23:30到现在的所有超警id
def get_agg_alert_id():
    now = datetime.now()
    # 将起始时间定位前一天23:30:00
    timefrom = int(((now - timedelta(days=1)).replace(hour=23, minute=30, second=0,microsecond=0)).timestamp() * 1000)
    timeto = int(now.timestamp() * 1000)
    # print("timefrom:",timefrom, datetime.fromtimestamp(timefrom/1000))
    # print("timeto:",timeto, datetime.fromtimestamp(timeto/1000))

    # 获取超级告警数量，全部为-1
    size = -1
    # 最大重发次数
    max_retries = 3
    id = set()

    url = ".../aggregate_log/list?startTime=" + str(timefrom) + "&endTime=" + str(timeto) + "&size=" + str(size)
    headers = {"Content-Type": "application/json"}
    try:
        for attempt in range(max_retries):
            resp = requests.get(url, headers=headers)

            if resp.status_code == 200:
                result = json.loads(resp.text)
                logs = result["data"]["records"]

                for log in logs:
                    id.add(log['id'])
                break
            
        if resp.status_code != 200:
            print('超警id三次获取都失败!')
        else:
            print('已有超级告警id获取完成...')
        return id
    except:
        print('超警id获取失败!')
        return set()


def upload_alerts(folder_path, aggregated_alerts_id, data):
    # url = 'test'
    url = ".../aggregate_log"
    headers = {"Content-Type": "application/json"}
    # 最大重发次数
    max_retries = 3

    for alert in data:
        # 重命名，规范接口数据
        alert["es_ids"] = alert.pop("ids")

        # 检测告警是否存在
        if alert["id"] in aggregated_alerts_id:
            endpoint = 'update'        
        else:
            endpoint = 'add'
        
        # 发送数据，失败则重发
        for attempt in range(max_retries):
            try:
                if endpoint == 'add':                    
                    resp = requests.post(f'{url}/add', headers = headers, data = json.dumps(alert))
                else:
                    resp = requests.put(f'{url}/update', headers = headers, data = json.dumps(alert))

                if resp.status_code == 200:
                    break
                else:
                    msg = json.loads(resp.text).get('msg')
                    # 检测是否是因为id已存在
                    match = re.search(r'Detail: Key \(id\)=\([a-f0-9]+\) already exists\.', msg)

                    if match:
                        endpoint = 'update'
                        print(f'{alert["id"]} already exists! (attempt: {attempt + 1}/{max_retries})')
                    else:
                        print(f'{alert["id"]} failed to upload! (attempt: {attempt + 1}/{max_retries})')
            
            except requests.RequestException as e:
                print(f'{alert["id"]} failed to upload! (attempt: {attempt + 1}/{max_retries}) due to an error: {e}')

        # 发送完成
        try:
            if resp.status_code != 200: 
                print(f'{alert["id"]} failed to upload after {max_retries} attemps! Info: {resp.text}')
                with open(f'{folder_path}/upload_failure_agg_alerts.json', 'a') as f:
                    json.dump(alert, f, indent=4, ensure_ascii=False)
                
            else:           
                # 已传输告警id
                aggregated_alerts_id.add(alert['id'])
        except:
            print(f'{alert["id"]} failed to upload! (attempt: {attempt + 1}/{max_retries})')
            with open(f'{folder_path}/upload_failure_agg_alerts.json', 'a') as f:
                    json.dump(alert, f, indent=4, ensure_ascii=False)
    
    # 获取list
    # try:
    #     resp = requests.get(f'{url}/list?size=1')
    #     result = json.dumps(json.loads(resp.text), indent = 4, ensure_ascii = False)
    #     print(result)
    # except:
    #     print('Failed to get list!')

    print('超级告警发送完成...')

    return aggregated_alerts_id


def get_keys_num():
    # 连接 Elasticsearch 客户端
    es = elasticsearch.Elasticsearch(...)

    logs_data_type = {
        "tianyan": {"sip", "dip", "rule_name"},
        "alarm-tianyan": {"sip", "dip", "vuln_type"},
        "zhongzi": {"sip", "dip", "event_name"},
        "v2zhongzi": {"sip", "dip", "msg"},
        "waf": {"src_ip", "dst_ip", "attack_type"}
    }

    result = {}
    # 最大重发次数
    max_retries = 3
    jud = True

    for logs_name, data_type in logs_data_type.items():
        result[logs_name] = {}

        for data in data_type:
            result[logs_name][data] = {}
            
            index_name = f"{logs_name}-*"
            query_body = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gt": "now-7d",      
                            "lt": "now"
                        }
                    }
                },
                "aggs": {
                    "top": {
                        "terms": {
                            "field": f"{data}.keyword",
                            "size": 1000000
                        }
                    }
                }      
            }
            
            for i in range(max_retries):
                try:
                    response = es.search(index=index_name, body=query_body)
                    hits = response['aggregations']["top"]['buckets']

                    for hit in hits:
                        result[logs_name][data][hit['key']] = hit['doc_count']

                    jud = True
                    break
                except Exception as e:
                    jud = False
                    print(f"历史关键词 {logs_name}: {data} 数量获取失败! 错误：{e} ({i + 1}/{max_retries})")

            if not jud:
                print(f"历史关键词 {logs_name}: {data} 数量获取失败!")
                break

        if not jud:
            break
                    
    if jud:
        print("历史关键词数量获取完成...")
        with open('keys_num.json', 'w', encoding='utf-8') as f:
            json.dump(result, f ,indent=4, ensure_ascii=False)
    else:
        print("历史关键词数量获取失败...")


def process_data(queue):
    stderr_file = open('process_data_err.log', 'a', encoding='utf-8')
    stdout_file = open('process_data.log', 'a', encoding='utf-8')
    
    # sys.stderr = stderr_file
    # sys.stdout = stdout_file
    
    base_dir = "./logs/"
    filters = {
        'tianyan': [...],
        'alarm-tianyan': [...],
        'zhongzi': [...],
        'v2zhongzi': [...],
        'waf': [...]
    }

    # 上次日志获取日期
    last_getlogs_date = ""
    try:
        while True:
            filename = queue.get(block=True)
            date = filename[:8]

            # print(f'date: {date}\nlast_time:{last_getlogs_date}')

            if date != last_getlogs_date:
                # 创建或清空初始变量
                sip_to_dip_connections = {}
                dip_to_sip_connections = {}
                all_filter_log_entries = []  # 累积所有处理过的日志条目
                aggregated_alerts = {}

                one_to_many_logs = []
                many_to_one_logs = []
                one_to_one_logs = []

                aggregated_alerts_id = get_agg_alert_id()
                # aggregated_alerts_id = set()

                # 获取关键词历史数量
                get_keys_num()


            file_path = os.path.join(base_dir, f"{filename}.json")
            filter_log_entries = []

            # 读取日志文件
            read_log_file(file_path, filter_log_entries)
            print(f"File: {filename}.json, Initial Entries: {len(filter_log_entries)}")

            # -----白名单-----
            filter_log_entries = filter_by_whitelist(filter_log_entries)
            print(f"File: {filename}.json, After White list Filtering: {len(filter_log_entries)}")

            # 时间去重
            filter_log_entries = time_deduplicate(filter_log_entries)
            print(f"File: {filename}.json, After Time Deduplication: {len(filter_log_entries)}")

            # 过滤特定攻击类型
            filter_log_entries = filter_by_attack_type(filter_log_entries, filters)
            print(f"File: {filename}.json, After Attack Type Filtering: {len(filter_log_entries)}")

            # 更新IP连接映射
            sip_to_dip_connections, dip_to_sip_connections = update_mappings(filter_log_entries, sip_to_dip_connections,
                                                                                dip_to_sip_connections)

            # 分类连接类型并保存数据
            one_to_many_logs = filter_one_to_many(sip_to_dip_connections)
            many_to_one_logs = filter_many_to_one(dip_to_sip_connections)
            one_to_one_logs = filter_one_to_one(sip_to_dip_connections, dip_to_sip_connections)

            # all_one_to_many_logs.extend(one_to_many_logs)
            # all_many_to_one_logs.extend(many_to_one_logs)
            # all_one_to_one_logs.extend(one_to_one_logs)
            all_filter_log_entries.extend([log_entry_to_dict(entry) for entry in filter_log_entries])
            update_aggregated_alerts(aggregated_alerts, filter_log_entries)

            print(f"Data for file {filename}.json processed.")

            print(f'all_filter_log_entries: {len(all_filter_log_entries)}')
            print(f'aggregated_alerts: {len(aggregated_alerts)}')

            # 将汇总数据保存到单个文件
            folder_path = f"./result/{date}"

            if not os.path.exists(folder_path):
                # 当文件夹不存在，创建
                os.makedirs(folder_path)

            with open(f'{folder_path}/filtered_log_entries.json', 'w', encoding='utf-8') as f:
                json.dump(all_filter_log_entries, f, indent=4, ensure_ascii=False)
            with open(f'{folder_path}/one_to_many_mappings.json', 'w', encoding='utf-8') as file:
                json.dump([mapping.to_dict() for mapping in one_to_many_logs], file, indent=4, ensure_ascii=False)
            with open(f'{folder_path}/many_to_one_mappings.json', 'w', encoding='utf-8') as file:
                json.dump([mapping.to_dict() for mapping in many_to_one_logs], file, indent=4, ensure_ascii=False)
            with open(f'{folder_path}/one_to_one_mappings.json', 'w', encoding='utf-8') as file:
                json.dump([mapping.to_dict() for mapping in one_to_one_logs], file, indent=4, ensure_ascii=False)
            
            json_data = [alert.to_dict() for alert in aggregated_alerts.values()]
            # 上传超级告警
            # aggregated_alerts_id = upload_alerts(folder_path, aggregated_alerts_id, json_data)
            with open(f'{folder_path}/aggregated_alerts.json', 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=4, ensure_ascii=False)

            print("All files processed and data saved.")
            print("------------------------------------------------------------\n")

            last_getlogs_date = date

            os.remove(file_path)
            stderr_file.flush()
            stdout_file.flush()

    except KeyboardInterrupt:
        print("------------------------------------------------------------\n")
        print("数据处理程序已中断")
        print("------------------------------------------------------------\n")

    finally:
        stderr_file.close()
        stdout_file.close()


if __name__ == '__main__':
    queue = Queue()
    process_data(queue)