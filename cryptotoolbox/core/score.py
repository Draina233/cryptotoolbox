"""密评分数计算（参照 C# cacscore v1.0 的评分模型实现）。

模型：
- 每个检测项有权重（0.4/0.7/1.0），得分取 0~1（符合程度）；
- 层面得分 = Σ(权重 × 得分) / Σ权重（四舍五入 4 位）；无适用项时为“不适用”；
- 技术层面（物理/网络/设备/应用）按 10/20/10/30 加权，管理层面（制度/人员/建设/应急）按 8/8/8/6 加权；
- 总分 = (技术加权平均 × 0.7 + 管理加权平均 × 0.3) × 100（四舍五入 4 位后乘 100）。

数据来自 E:\\source\\cacscore_v1.0\\cacscore\\Form1.cs（GBK），由脚本解析生成，未手工改动权重。
"""
from __future__ import annotations

import json
from decimal import ROUND_HALF_UP, Decimal

_DATA = r"""{"2":{"layers":[{"name":"物理层","items":[{"box":"1","weight":0.7,"name":"（宜）身份鉴别","default":true},{"box":"2","weight":0.4,"name":"（可）电子门禁记录数据存储完整性","default":true}]},{"name":"网络层","items":[{"box":"3","weight":0.7,"name":"（宜）身份鉴别","default":true},{"box":"5","weight":0.4,"name":"（可）通信数据完整性","default":true},{"box":"7","weight":0.7,"name":"（宜）通信过程中重要数据机密性","default":true},{"box":"6","weight":0.4,"name":"（可）网络边界访问控制信息完整性","default":true}]},{"name":"设备层","items":[{"box":"13","weight":0.7,"name":"（宜）身份鉴别","default":true},{"box":"11","weight":0.4,"name":"（可）系统访问控制信息完整性","default":true},{"box":"9","weight":0.4,"name":"（可）日志记录完整性","default":true}]},{"name":"应用层","items":[{"box":"20","weight":0.7,"name":"（宜）身份鉴别","default":true},{"box":"19","weight":0.4,"name":"（可）访问控制信息完整性","default":true},{"box":"17","weight":0.7,"name":"（宜）重要数据传输机密性","default":true},{"box":"16","weight":0.7,"name":"（宜）重要数据存储机密性","default":true},{"box":"15","weight":0.7,"name":"（宜）重要数据传输完整性","default":true},{"box":"21","weight":0.7,"name":"（宜）重要数据存储完整性","default":true}]},{"name":"管理制度","items":[{"box":"28","weight":1.0,"name":"（应）具备密码应用安全管理制度","default":true},{"box":"27","weight":0.7,"name":"（应）密钥管理规则","default":true},{"box":"26","weight":0.7,"name":"（应）建立操作规程","default":true}]},{"name":"人员管理","items":[{"box":"34","weight":0.7,"name":"（应）了解并遵守相关法律制度","default":true},{"box":"33","weight":1.0,"name":"（应）建立岗位责任制度","default":true},{"box":"32","weight":0.7,"name":"（应）建立上岗人员培训制度","default":true},{"box":"30","weight":0.7,"name":"（应）建立保密制度和调离制度","default":true}]},{"name":"建设运行","items":[{"box":"38","weight":1.0,"name":"（应）制定密码应用方案","default":true},{"box":"37","weight":1.0,"name":"（应）制定密钥安全管理策略","default":true},{"box":"36","weight":0.7,"name":"（应）制定实施方案","default":true},{"box":"35","weight":1.0,"name":"（宜）投入运行前进行密评","default":true}]},{"name":"应急处置","items":[{"box":"43","weight":1.0,"name":"（应）应急策略","default":true}]}],"total":[{"label":"24","group":"jishu","weight":10.0},{"label":"23","group":"jishu","weight":20.0},{"label":"22","group":"jishu","weight":10.0},{"label":"21","group":"jishu","weight":30.0},{"label":"20","group":"guanli","weight":8.0},{"label":"19","group":"guanli","weight":8.0},{"label":"18","group":"guanli","weight":8.0},{"label":"17","group":"guanli","weight":6.0}],"coef":[0.7,0.3]},"3":{"layers":[{"name":"物理层","items":[{"box":"1","weight":1.0,"name":"（宜）身份鉴别","default":true},{"box":"2","weight":0.7,"name":"（宜）电子门禁记录数据存储完整性","default":true},{"box":"4","weight":0.7,"name":"（宜）视频记录数据存储完整性","default":true}]},{"name":"网络层","items":[{"box":"3","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"5","weight":0.7,"name":"（宜）通信数据完整性","default":true},{"box":"7","weight":1.0,"name":"（应）通信过程中重要数据机密性","default":true},{"box":"6","weight":0.4,"name":"（宜）网络边界访问控制信息完整性","default":true},{"box":"8","weight":0.4,"name":"（可）安全接入认证","default":false}]},{"name":"设备层","items":[{"box":"13","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"12","weight":1.0,"name":"（应）远程管理通道安全","default":true},{"box":"11","weight":0.4,"name":"（宜）系统访问控制信息完整性","default":true},{"box":"10","weight":0.4,"name":"（宜）重要信息资源安全标记完整性","default":true},{"box":"9","weight":0.4,"name":"（宜）日志记录完整性","default":true},{"box":"14","weight":0.7,"name":"（宜）重要可执行程序完整性、\\r\\n重要可执行程序来源真实性","default":true}]},{"name":"应用层","items":[{"box":"20","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"19","weight":0.4,"name":"（宜）访问控制信息完整性","default":true},{"box":"18","weight":0.4,"name":"（宜）重要信息资源安全标记完整性","default":true},{"box":"17","weight":1.0,"name":"（应）重要数据传输机密性","default":true},{"box":"16","weight":1.0,"name":"（应）重要数据存储机密性","default":true},{"box":"15","weight":0.7,"name":"（宜）重要数据传输完整性","default":true},{"box":"21","weight":0.7,"name":"（宜）重要数据存储完整性","default":true},{"box":"22","weight":1.0,"name":"（宜）不可否认性","default":false}]},{"name":"管理制度","items":[{"box":"28","weight":1.0,"name":"（应）具备密码应用安全管理制度","default":true},{"box":"27","weight":0.7,"name":"（应）密钥管理规则","default":true},{"box":"26","weight":0.7,"name":"（应）建立操作规程","default":true},{"box":"25","weight":0.7,"name":"（应）定期修订安全管理制度","default":true},{"box":"24","weight":0.7,"name":"（应）明确管理制度发布流程","default":true},{"box":"23","weight":0.7,"name":"（应）制度执行过程记录留存","default":true}]},{"name":"人员管理","items":[{"box":"34","weight":0.7,"name":"（应）了解并遵守相关法律制度","default":true},{"box":"33","weight":1.0,"name":"（应）建立岗位责任制度","default":true},{"box":"32","weight":0.7,"name":"（应）建立上岗人员培训制度","default":true},{"box":"31","weight":0.7,"name":"（应）定期进行安全岗位人员考核","default":true},{"box":"30","weight":0.7,"name":"（应）建立保密制度和调离制度","default":true}]},{"name":"建设运行","items":[{"box":"38","weight":1.0,"name":"（应）制定密码应用方案","default":true},{"box":"37","weight":1.0,"name":"（应）制定密钥安全管理策略","default":true},{"box":"36","weight":0.7,"name":"（应）制定实施方案","default":true},{"box":"35","weight":1.0,"name":"（应）投入运行前进行密评","default":true},{"box":"29","weight":0.7,"name":"（应）定期密评与攻防演习","default":true}]},{"name":"应急处置","items":[{"box":"43","weight":1.0,"name":"（应）应急策略","default":true},{"box":"42","weight":0.7,"name":"（应）事件处置","default":true},{"box":"41","weight":0.7,"name":"（应）向有关主管部门上报处置情况","default":true}]}],"total":[{"label":"24","group":"jishu","weight":10.0},{"label":"23","group":"jishu","weight":20.0},{"label":"22","group":"jishu","weight":10.0},{"label":"21","group":"jishu","weight":30.0},{"label":"20","group":"guanli","weight":8.0},{"label":"19","group":"guanli","weight":8.0},{"label":"18","group":"guanli","weight":8.0},{"label":"17","group":"guanli","weight":6.0}],"coef":[0.7,0.3]},"4":{"layers":[{"name":"物理层","items":[{"box":"1","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"2","weight":0.7,"name":"（应）电子门禁记录数据存储完整性","default":true},{"box":"4","weight":0.7,"name":"（应）视频记录数据存储完整性","default":true}]},{"name":"网络层","items":[{"box":"3","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"5","weight":1.0,"name":"（应）通信数据完整性","default":true},{"box":"7","weight":1.0,"name":"（应）通信过程中重要数据机密性","default":true},{"box":"6","weight":0.7,"name":"（应）网络边界访问控制信息完整性","default":true},{"box":"8","weight":0.7,"name":"（宜）安全接入认证","default":true}]},{"name":"设备层","items":[{"box":"13","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"12","weight":1.0,"name":"（应）远程管理通道安全","default":true},{"box":"11","weight":0.7,"name":"（应）系统访问控制信息完整性","default":true},{"box":"10","weight":0.7,"name":"（应）重要信息资源安全标记完整性","default":true},{"box":"9","weight":0.7,"name":"（应）日志记录完整性","default":true},{"box":"14","weight":1.0,"name":"（应）重要可执行程序完整性、\\r\\n重要可执行程序来源真实性","default":true}]},{"name":"应用层","items":[{"box":"20","weight":1.0,"name":"（应）身份鉴别","default":true},{"box":"19","weight":0.7,"name":"（应）访问控制信息完整性","default":true},{"box":"18","weight":0.7,"name":"（应）重要信息资源安全标记完整性","default":true},{"box":"17","weight":1.0,"name":"（应）重要数据传输机密性","default":true},{"box":"16","weight":1.0,"name":"（应）重要数据存储机密性","default":true},{"box":"15","weight":1.0,"name":"（应）重要数据传输完整性","default":true},{"box":"21","weight":1.0,"name":"（应）重要数据存储完整性","default":true},{"box":"22","weight":1.0,"name":"（应）不可否认性","default":true}]},{"name":"管理制度","items":[{"box":"28","weight":1.0,"name":"（应）具备密码应用安全管理制度","default":true},{"box":"27","weight":0.7,"name":"（应）密钥管理规则","default":true},{"box":"26","weight":0.7,"name":"（应）建立操作规程","default":true},{"box":"25","weight":0.7,"name":"（应）定期修订安全管理制度","default":true},{"box":"24","weight":0.7,"name":"（应）明确管理制度发布流程","default":true},{"box":"23","weight":0.7,"name":"（应）制度执行过程记录留存","default":true}]},{"name":"人员管理","items":[{"box":"34","weight":0.7,"name":"（应）了解并遵守相关法律制度","default":true},{"box":"33","weight":1.0,"name":"（应）建立岗位责任制度","default":true},{"box":"32","weight":0.7,"name":"（应）建立上岗人员培训制度","default":true},{"box":"31","weight":0.7,"name":"（应）定期进行安全岗位人员考核","default":true},{"box":"30","weight":0.7,"name":"（应）建立保密制度和调离制度","default":true}]},{"name":"建设运行","items":[{"box":"38","weight":1.0,"name":"（应）制定密码应用方案","default":true},{"box":"37","weight":1.0,"name":"（应）制定密钥安全管理策略","default":true},{"box":"36","weight":0.7,"name":"（应）制定实施方案","default":true},{"box":"35","weight":1.0,"name":"（应）投入运行前进行密评","default":true},{"box":"29","weight":0.7,"name":"（应）定期密评与攻防演习","default":true}]},{"name":"应急处置","items":[{"box":"43","weight":1.0,"name":"（应）应急策略","default":true},{"box":"42","weight":0.7,"name":"（应）事件处置","default":true},{"box":"41","weight":0.7,"name":"（应）向有关主管部门上报处置情况","default":true}]}],"total":[{"label":"24","group":"jishu","weight":10.0},{"label":"23","group":"jishu","weight":20.0},{"label":"22","group":"jishu","weight":10.0},{"label":"21","group":"jishu","weight":30.0},{"label":"20","group":"guanli","weight":8.0},{"label":"19","group":"guanli","weight":8.0},{"label":"18","group":"guanli","weight":8.0},{"label":"17","group":"guanli","weight":6.0}],"coef":[0.7,0.3]}}"""
LEVELS: dict = json.loads(_DATA)
for _level in LEVELS.values():
    for _layer in _level["layers"]:
        for _item in _layer["items"]:
            name = _item["name"]
            for _sep in (chr(92) + "n", chr(92) + "r", chr(10), chr(13)):
                name = name.replace(_sep, " ")
            _item["name"] = " ".join(name.split())


LAYER_TITLES = ("物理和环境安全", "网络和通信安全", "设备和计算安全", "应用和数据安全",
               "管理制度", "人员管理", "建设运行", "应急处置")
TECH_LAYER_NAMES = LAYER_TITLES[:4]
MGMT_LAYER_NAMES = LAYER_TITLES[4:]
LAYER_ORDER = LAYER_TITLES


LEVEL_TITLES = {"2": "第二级", "3": "第三级", "4": "第四级"}


def round4(value: float) -> float:
    return float(Decimal(str(value)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))


def layer_items(level: str) -> list[dict]:
    return LEVELS[str(level)]["layers"]


def layer_score(items: list[dict], scores: dict[int, float]) -> tuple[str, float | None]:
    """返回 (状态, 得分)。状态：ok / 不适用 / 参数错误。"""
    total_weight = 0.0
    total = 0.0
    for index, item in enumerate(items):
        if index not in scores:
            continue
        score = scores[index]
        if score is None or not (0.0 <= float(score) <= 1.0):
            return "参数错误", None
        total_weight += item["weight"]
        total += float(score) * item["weight"]
    if total_weight == 0:
        return "不适用", None
    return "ok", round4(total / total_weight)


def compute(level: str, scores_by_layer: list[dict[int, float]]) -> dict:
    """scores_by_layer: 每个层面 {项目下标: 0~1 得分}；未给出的项视为不适用。"""
    level = str(level)
    data = LEVELS[level]
    layers = []
    technical = []
    management = []
    technical_weight = 0.0
    management_weight = 0.0
    for layer_index, layer in enumerate(data["layers"]):
        status, score = layer_score(layer["items"], scores_by_layer[layer_index])
        if status == "参数错误":
            layers.append({"name": LAYER_TITLES[layer_index], "status": "参数错误", "score": None})
            return {"status": "参数错误", "layers": layers, "total": None}
        layers.append({"name": LAYER_TITLES[layer_index], "status": status, "score": score})
        weight = data["total"][layer_index]["weight"]
        if layer_index < 4 and score is not None:
            technical.append(score * weight)
            technical_weight += weight
        elif score is not None:
            management.append(score * weight)
            management_weight += weight
    if technical_weight == 0 or management_weight == 0:
        return {"status": "无法计算", "layers": layers, "total": None}
    tech_avg = round4(sum(technical) / technical_weight)
    mgmt_avg = round4(sum(management) / management_weight)
    coef = data["coef"]
    total = round4(tech_avg * coef[0] + mgmt_avg * coef[1])
    return {
        "status": "ok", "layers": layers,
        "technical": tech_avg, "management": mgmt_avg,
        "coef": coef, "total": round4(total * 100),
    }
