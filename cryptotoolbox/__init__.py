"""优悠密评百宝箱 v2 —— 离线商用密码应用安全评估工具箱。

核心设计：
- core/   纯逻辑层，零 Qt 依赖，可单独用 unittest 测试
- ui/     界面层，只负责输入收集与结果展示
- 所有密码学运算均基于成熟实现（gmalg / tongsuopy / pycryptodome）并以官方向量回归
"""

__version__ = "2.0.5"
__app_name__ = "优悠密评百宝箱"
__app_subtitle__ = "离线密码评估与验证"
