class LogEntry:
    def __init__(self, log_type, id, sip, dip, sport, dport, timestamp,
                 attack_type, attack_result, severity,
                 req_header, req_body, rsp_header, rsp_body, packet_data,
                 threat_status, filtered_stage, related_alerts_ids):
        self.log_type = log_type
        self.id = id
        self.sip = sip
        self.dip = dip
        self.sport = sport
        self.dport = dport
        self.timestamp = timestamp
        self.attack_type = attack_type
        self.attack_result = attack_result
        self.severity = severity
        self.req_header = req_header
        self.req_body = req_body
        self.rsp_header = rsp_header
        self.rsp_body = rsp_body
        self.packet_data = packet_data
        self.threat_status = threat_status
        self.filtered_stage = filtered_stage
        self.related_alerts_ids = related_alerts_ids

    def __repr__(self):
        return (
            f"LogEntry(log_type={self.log_type}, index={self.id}, sip={self.sip}, dip={self.dip}, sport={self.sport}, dport={self.dport},"
            f"timestamp={self.timestamp}, attack_type={self.attack_type}, attack_result={self.attack_result}, "
            f"severity={self.severity}, req_header={self.req_header}, req_body={self.req_body}, "
            f"rsp_header={self.rsp_header}, rsp_body={self.rsp_body}, packet_data={self.packet_data}), "
            f"threat_status={self.threat_status}, filtered_stage={self.filtered_stage}, related_alerts_ids={self.related_alerts_ids}")


class SiptoNDipMapping:
    def __init__(self, sip):
        self.sip = sip
        self.dips = {}

    def add_dip(self, dip, log_id, attack_type):
        if dip not in self.dips:
            self.dips[dip] = {}
        if attack_type not in self.dips[dip]:
            self.dips[dip][attack_type] = []
        self.dips[dip][attack_type].append(log_id)

    def to_dict(self):
        return {
            'sip': self.sip,
            'dips': self.dips
        }

    def __repr__(self):
        return f"SIP: {self.sip}, DIPs: {self.dips}"


class DiptoNSipMapping:
    def __init__(self, dip):
        self.dip = dip
        self.sips = {}

    def add_sip(self, sip, log_id, attack_type):
        if sip not in self.sips:
            self.sips[sip] = {}
        if attack_type not in self.sips[sip]:
            self.sips[sip][attack_type] = []
        self.sips[sip][attack_type].append(log_id)

    def to_dict(self):
        return {
            'dip': self.dip,
            'sips': self.sips
        }

    def __repr__(self):
        return f"DIP: {self.dip}, SIPs: {self.sips}, Many-to-One: {len(self.sips) > 1}"


class AggregatedAlert:
    def __init__(self, id, log_type, sip, dip, earliest_time, latest_time, attack_type,
                 llm_score, entropy_score, rule_score, total_score, ids):
        self.id = id                      # 唯一标识符
        self.log_type = log_type          # 告警日志类别
        self.sip = sip                    # 源IP
        self.dip = dip                    # 目的IP
        self.earliest_time = earliest_time  # 最早发生时间
        self.latest_time = latest_time    # 最新发生时间
        self.attack_type = attack_type    # 攻击类型
        self.llm_score = llm_score        # 大模型评分
        self.entropy_score = entropy_score  # 信息熵评分
        self.rule_score = rule_score      # 规则评分
        self.total_score = total_score    # 总分
        self.num_alerts = len(ids)        # 动态记录ids列表的长度
        self.ids = ids                    # 这类聚合告警包含的元告警ID列表

    def to_dict(self):
        return {
            "id": self.id,
            "log_type": self.log_type,
            "sip": self.sip,
            "dip": self.dip,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "attack_type": self.attack_type,
            "llm_score": self.llm_score,
            "entropy_score": self.entropy_score,
            "rule_score": self.rule_score,
            "total_score": self.total_score,
            "num_alerts": self.num_alerts,
            "ids": self.ids
        }

    def __repr__(self):
        return (f"AggregatedAlert(id={self.id}, log_type={self.log_type}, sip={self.sip}, dip={self.dip}, "
                f"earliest_time={self.earliest_time}, latest_time={self.latest_time}, "
                f"attack_type={self.attack_type}, llm_score={self.llm_score}, "
                f"entropy_score={self.entropy_score}, rule_score={self.rule_score}, "
                f"total_score={self.total_score}, num_alerts={self.num_alerts}), ids={self.ids}")

