# 悠优密评百宝箱 · 第三方声明（NOTICE）

本项目在实现与测试中使用了以下第三方资源，特此声明：

## guojuntang/gmt_randomness_test（BSD-3-Clause）

- 来源：https://github.com/guojuntang/gmt_randomness_test
- 用途：GM/T 0005-2021 随机性检测的参考实现与参数/公式对照；本项目在此基础上重写为 numpy 向量化实现，
  并修复了参考实现中的数值缺陷（numpy 2.x 兼容、矩阵秩输入被就地修改、q 值分箱区间等）。
- 许可证：BSD 3-Clause（Copyright (c) 2023, Guojun Tang）。原许可证文本：
  <https://opensource.org/licenses/BSD-3-Clause>。该许可证要求保留版权声明、条件与免责声明，
  且不得以版权人名义为衍生产品背书。

## 应用图标

- 图标文件：`cryptotoolbox/assets/app_icon.ico`、`app_icon_*.png`
- 图标署名：`悠优密评百宝箱`（©Draina）

## 测试向量来源

- SM3：GB/T 32905-2016 附录 A 示例
- SM4：GM/T 0002-2012 标准向量
- SM2：GM/T 0003.5-2012 附录 A 示例曲线向量；官方推荐曲线向量取自 Botan 测试数据
  （https://github.com/randombit/botan，BSD-2-Clause），并与 gmalg 交叉验证
- AES / DES / 3DES：NIST FIPS-197、FIPS 46-3、NIST SP 800-38A 附录 F
- GCM：NIST GCM 规范测试向量（McGrew & Viega）
- XTS：IEEE P1619/D16 Annex B 测试向量
- CMAC：NIST SP 800-38B 示例
- HMAC：RFC 2202、RFC 4231
- RSA：RFC 8017 示例
- GM/T 0005-2021：检测项、参数与 P/Q 判定口径依据标准正文；Appendix A/C 的完整参数表与结果示例
  在实现时以公开资料与参考实现交叉核对，差异记录见 docs/accuracy.md

## 运行依赖及其许可证（摘要）

| 依赖 | 许可证 |
|---|---|
| PySide6 | LGPL-3.0（Qt for Python） |
| gmalg | 见包元数据（纯 Python 国密算法库） |
| tongsuopy | Apache-2.0（BabaSSL/Tongsuo 的 Python 绑定） |
| PyCryptodome | BSD-2-Clause |
| pypdf | BSD-3-Clause |
| numpy | BSD-3-Clause |
| gmssl / asn1crypto（仅测试交叉对照） | MIT / MIT |

本项目的 ASN.1/X.509/CMS/CRL 解析、SM2 曲线运算、PCAP 解析与界面代码为本项目自研实现。
