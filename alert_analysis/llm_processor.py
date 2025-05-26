# Token 大小分析
# Qwen2.5-14B 的 Token 限制
# 上下文长度: Qwen2.5-14B 支持最大 32K tokens (约 24,000-28,000 中文字符)
# 建议单次输入: 保持在 8K-16K tokens 以确保推理效率和稳定性
# 预留空间: 为输出结果预留 500-1000 tokens
# 告警日志 Token 估算
# 单条告警的主要字段：

# 单条告警的 token 估算
# 字段估算
{
    "attack_type": "10-30 tokens",
    "req_header": "50-200 tokens", 
    "req_body": "20-500 tokens",
    "packet_data": "100-2000 tokens (需截断)",
    "log_type": "5-10 tokens",
    "基础信息(IP/端口等)": "20-50 tokens"
}
# 单条告警总计: 约 200-2800 tokens

# 输入流程设计

# 1. 批量处理策略
import tiktoken
from typing import List, Dict, Any

class LLMBatchProcessor:
    def __init__(self, model_name="qwen2.5-14b"):
        self.max_context_tokens = 30000  # 预留安全边界
        self.max_single_batch_tokens = 15000  # 单批次限制
        self.output_reserve_tokens = 1000  # 为输出预留
        self.tokenizer = tiktoken.get_encoding("cl100k_base")  # 或使用 Qwen 专用 tokenizer
    
    def estimate_tokens(self, text: str) -> int:
        """估算文本的 token 数量"""
        return len(self.tokenizer.encode(text))
    
    def prepare_alert_batch(self, aggregated_alerts: List[Dict]) -> List[List[Dict]]:
        """将聚合告警分批处理"""
        batches = []
        current_batch = []
        current_tokens = 0
        
        # 基础 Prompt token 消耗
        base_prompt_tokens = self.estimate_tokens(self.get_base_prompt())
        
        for alert in aggregated_alerts:
            alert_text = self.format_alert_for_llm(alert)
            alert_tokens = self.estimate_tokens(alert_text)
            
            # 检查是否需要截断单个告警
            if alert_tokens > 2000:  # 单个告警 token 限制
                alert_text = self.truncate_alert_content(alert_text, 2000)
                alert_tokens = 2000
            
            # 检查批次容量
            if (current_tokens + alert_tokens + base_prompt_tokens + self.output_reserve_tokens 
                > self.max_single_batch_tokens):
                if current_batch:
                    batches.append(current_batch)
                current_batch = [alert]
                current_tokens = alert_tokens
            else:
                current_batch.append(alert)
                current_tokens += alert_tokens
        
        if current_batch:
            batches.append(current_batch)
        
        return batches


# 2. 内容截断策略
class AlertContentTruncator:
    def __init__(self):
        self.field_priorities = {
            "attack_type": 1.0,      # 最高优先级
            "req_header": 0.7,       # 高优先级
            "req_body": 0.6,         # 中高优先级
            "packet_data": 0.3,      # 低优先级，可大幅截断
            "log_type": 1.0,         # 最高优先级
        }
        self.field_max_tokens = {
            "attack_type": 50,
            "req_header": 300,
            "req_body": 400,
            "packet_data": 500,      # 从可能的 2000+ tokens 截断到 500
            "log_type": 20,
        }
    
    def truncate_alert_content(self, alert_dict: Dict, max_tokens: int) -> Dict:
        """智能截断告警内容"""
        truncated_alert = alert_dict.copy()
        
        # 按优先级截断
        for field, max_field_tokens in self.field_max_tokens.items():
            if field in truncated_alert and truncated_alert[field]:
                content = str(truncated_alert[field])
                if self.estimate_tokens(content) > max_field_tokens:
                    # 保留前80%和后20%的重要内容
                    if field == "packet_data":
                        truncated_alert[field] = self.smart_truncate_packet_data(content, max_field_tokens)
                    else:
                        truncated_alert[field] = self.truncate_text(content, max_field_tokens)
        
        return truncated_alert
    
    def smart_truncate_packet_data(self, packet_data: str, max_tokens: int) -> str:
        """智能截断数据包内容"""
        # 保留数据包头部（通常包含关键信息）和尾部
        front_ratio = 0.7
        back_ratio = 0.3
        
        target_chars = max_tokens * 3  # 粗略 token-char 转换
        front_chars = int(target_chars * front_ratio)
        back_chars = int(target_chars * back_ratio)
        
        if len(packet_data) <= target_chars:
            return packet_data
        
        return (packet_data[:front_chars] + 
                f"\n... [截断 {len(packet_data) - front_chars - back_chars} 字符] ...\n" + 
                packet_data[-back_chars:])
        
# 3. Prompt 优化
class AlertPromptBuilder:
    def __init__(self):
        self.base_prompt_template = """
你是一个网络安全告警分析专家。请分析以下告警信息，给出0-100的威胁评分。

评分标准：
- 0-30: 低风险/误报可能性高
- 31-60: 中等风险/需要关注  
- 61-85: 高风险/可能恶意
- 86-100: 严重威胁/确认恶意

分析要点：
1. 攻击类型的严重程度
2. 请求头/请求体的异常特征
3. 数据包内容的可疑模式
4. 结合安全知识判断真实威胁

告警信息：
{alert_content}

请仅输出评分数字(0-100)："""

    def build_batch_prompt(self, alerts_batch: List[Dict]) -> str:
        """构建批量处理的 Prompt"""
        alerts_content = ""
        
        for i, alert in enumerate(alerts_batch, 1):
            alert_content = f"""
告警 {i}:
- 攻击类型: {alert.get('attack_type', 'Unknown')}
- 日志类型: {alert.get('log_type', 'Unknown')}
- 源IP: {alert.get('sip', 'Unknown')} -> 目标IP: {alert.get('dip', 'Unknown')}
- 请求头: {self.truncate_if_needed(alert.get('req_header', ''), 150)}
- 请求体: {self.truncate_if_needed(alert.get('req_body', ''), 200)}
- 数据包片段: {self.truncate_if_needed(alert.get('packet_data', ''), 200)}
"""
            alerts_content += alert_content
        
        # 批量处理的 Prompt 模板
        batch_prompt = f"""
你是网络安全告警分析专家。请分析以下 {len(alerts_batch)} 条告警，为每条给出0-100的威胁评分。

{alerts_content}

请按格式输出：
告警1评分: [数字]
告警2评分: [数字]
...
告警{len(alerts_batch)}评分: [数字]
"""
        return batch_prompt
    
    
# 4. 流量控制策略
import asyncio
import time
from typing import List

class LLMFlowController:
    def __init__(self):
        self.max_concurrent_requests = 3  # 并发请求限制
        self.request_interval = 1.0       # 请求间隔(秒)
        self.max_retry_times = 3          # 最大重试次数
        self.timeout_seconds = 30         # 单次请求超时
        
    async def process_alerts_with_llm(self, aggregated_alerts: List[Dict]) -> List[Dict]:
        """控制流量处理告警"""
        processor = LLMBatchProcessor()
        batches = processor.prepare_alert_batch(aggregated_alerts)
        
        print(f"总共 {len(aggregated_alerts)} 条告警，分为 {len(batches)} 批次处理")
        
        # 并发处理批次
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        tasks = []
        
        for i, batch in enumerate(batches):
            task = self.process_single_batch(semaphore, batch, i)
            tasks.append(task)
            
            # 控制请求频率
            if i > 0:
                await asyncio.sleep(self.request_interval)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 合并结果
        all_scored_alerts = []
        for result in results:
            if isinstance(result, list):
                all_scored_alerts.extend(result)
            else:
                print(f"批次处理失败: {result}")
        
        return all_scored_alerts
    
    async def process_single_batch(self, semaphore: asyncio.Semaphore, 
                                 batch: List[Dict], batch_id: int) -> List[Dict]:
        """处理单个批次"""
        async with semaphore:
            for attempt in range(self.max_retry_times):
                try:
                    # 调用 LLM API
                    prompt = AlertPromptBuilder().build_batch_prompt(batch)
                    
                    # 这里调用实际的 LLM API
                    response = await self.call_llm_api(prompt)
                    scores = self.parse_batch_scores(response, len(batch))
                    
                    # 将评分写回告警对象
                    for i, alert in enumerate(batch):
                        alert['llm_score'] = scores[i] if i < len(scores) else 50  # 默认分数
                    
                    print(f"批次 {batch_id} 处理完成，包含 {len(batch)} 条告警")
                    return batch
                    
                except Exception as e:
                    print(f"批次 {batch_id} 第 {attempt + 1} 次尝试失败: {e}")
                    if attempt < self.max_retry_times - 1:
                        await asyncio.sleep(2 ** attempt)  # 指数退避
                    else:
                        # 最终失败，设置默认分数
                        for alert in batch:
                            alert['llm_score'] = 50  # 默认中等风险分数
                        return batch
# 建议的配置参数

LLM_CONFIG = {
    "model_settings": {
        "max_context_tokens": 30000,
        "max_batch_tokens": 15000,
        "single_alert_max_tokens": 2000,
        "output_reserve_tokens": 1000,
    },
    
    "batch_processing": {
        "max_alerts_per_batch": 10,  # 每批次最大告警数
        "max_concurrent_batches": 3,
        "request_interval_seconds": 1.0,
    },
    
    "content_limits": {
        "packet_data_max_chars": 1500,  # 约500 tokens
        "req_header_max_chars": 900,    # 约300 tokens  
        "req_body_max_chars": 1200,     # 约400 tokens
    },
    
    "retry_policy": {
        "max_retries": 3,
        "timeout_seconds": 30,
        "backoff_factor": 2,
    }
}
