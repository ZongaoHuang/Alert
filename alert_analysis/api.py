from flask import Flask, request, jsonify
import toml
from wlredis import WhitelistManager

app = Flask(__name__)


# 读取 TOML 文件，获取默认 TTL 时间
def read_ttl_from_toml(toml_file):
    """
    从 TOML 文件中读取默认 TTL 时间
    :param toml_file: TOML 文件路径
    :return: 默认的 TTL 时间（秒）
    """
    config = toml.load(toml_file)
    return config["settings"]["default_ttl"]


# 增加白名单的 API 接口
@app.route('/whitelist/add_whitelist', methods=['POST'])
def add_whitelist():
    """
    增加白名单接口，接收 JSON 数据并添加到白名单中
    """
    try:
        # 获取 JSON 数据
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        # 从 JSON 数据中提取六元组字段
        six_tuple = (
            data.get("log_type"),
            data.get("sip"),
            data.get("dip"),
            data.get("sport"),
            data.get("dport"),
            data.get("attack_type")
        )

        # 读取默认 TTL 时间
        ttl = read_ttl_from_toml("config.toml")

        # 创建 WhitelistManager 实例
        whitelist_manager = WhitelistManager()

        # 添加到白名单
        whitelist_manager.add_to_whitelist(six_tuple, ttl)
        return jsonify({"message": "Whitelist entry added", "six_tuple": six_tuple, "ttl": ttl}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 删除白名单的 API 接口
@app.route('/whitelist/remove_whitelist', methods=['DELETE'])
def remove_whitelist():
    """
    删除白名单接口，接收 JSON 数据并从白名单中删除指定条目
    """
    try:
        # 获取 JSON 数据
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        print(data)

        # 从 JSON 数据中提取六元组字段
        six_tuple = (
            data.get("log_type"),
            data.get("sip"),
            data.get("dip"),
            data.get("sport"),
            data.get("dport"),
            data.get("attack_type")
        )

        # 创建 WhitelistManager 实例
        whitelist_manager = WhitelistManager()

        # 删除白名单条目
        success = whitelist_manager.remove_from_whitelist(six_tuple)
        if success:
            return jsonify({"message": "Whitelist entry removed", "six_tuple": six_tuple}), 200
        else:
            return jsonify({"error": "Whitelist entry not found", "six_tuple": six_tuple}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 查询白名单的 API 接口
@app.route('/whitelist/query_whitelist', methods=['GET'])
def query_whitelist():
    """
    查询白名单接口，接收 JSON 数据并查询指定白名单条目
    """
    try:
        # 获取 JSON 数据
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400

        print(data)

        # 从 JSON 数据中提取六元组字段
        six_tuple = (
            data.get("log_type"),
            data.get("sip"),
            data.get("dip"),
            data.get("sport"),
            data.get("dport"),
            data.get("attack_type")
        )

        # 创建 WhitelistManager 实例
        whitelist_manager = WhitelistManager()

        # 查询白名单条目
        result = whitelist_manager.get_whitelist_item(six_tuple)
        if result:
            return jsonify({"message": "Whitelist entry found", "six_tuple": six_tuple, "data": result}), 200
        else:
            return jsonify({"error": "Whitelist entry not found", "six_tuple": six_tuple}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 获取所有白名单项
@app.route('/whitelist/get_all_whitelists', methods=['GET'])
def get_all_whitelists():
    """
    获取所有白名单项的接口
    """
    try:
        # 创建 WhitelistManager 实例
        whitelist_manager = WhitelistManager()

        # 获取所有白名单条目
        all_items = whitelist_manager.get_all_whitelist_items()
        return jsonify({"message": "All whitelist entries retrieved", "data": all_items}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 主入口
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
