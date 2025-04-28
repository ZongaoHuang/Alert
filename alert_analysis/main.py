# main.py
import time
import multiprocessing
from get_logs import get_logs
from process_data import process_data


def restart_process(process, target, args, name):
    # 检查进程是否存活，如果崩溃则重新启动
    if not process.is_alive():
        print(f"进程 {process.name} 崩溃，正在重启...")
        process = multiprocessing.Process(target=target, args=args, name=name)

        # 启动
        process.start()

    return process


if __name__ == '__main__':
    # 创建队列对象
    queue = multiprocessing.Queue()

    # 创建两个进程
    get_logs_process = multiprocessing.Process(target=get_logs, args=(queue,), name='get_logs')
    process_data_process = multiprocessing.Process(target=process_data, args=(queue,), name='process_data')

    # 启动进程
    get_logs_process.start()
    process_data_process.start()

    try:
        while True:
            # 监控进程，如果进程崩溃则重启
            get_logs_process = restart_process(get_logs_process, get_logs, (queue,), 'get_logs')
            process_data_process = restart_process(process_data_process, process_data, (queue,), 'process_data')
            
            time.sleep(10)  # 每隔60秒检查一次进程状态
    except KeyboardInterrupt:
        time.sleep(0.5)
        print("程序终止，关闭所有进程...")
    finally:
        # 结束进程
        get_logs_process.terminate()
        process_data_process.terminate()
        get_logs_process.join()
        process_data_process.join()
