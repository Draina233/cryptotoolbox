# 密评工具箱 v2（CryptoEval Toolbox）

面向**商用密码应用安全性评估（密评）**的离线验证工具箱：算法校验、证书与签章核验、协议取证、随机性检测。
所有运算均在本机完成，不依赖网络与外部服务。

## 功能清单（6 大类 19 个功能页）

| 分类 | 功能页 | 说明 |
|---|---|---|
| 常用工具 | 分数计算 | 按密评评分模型（参照 C# cacscore v1.0）：检测项加权 → 层面得分 → 技术/管理加权 → 总分，并统计符合/部分符合/不符合/不适用项数 |
| 常用工具 | 常见编码转换 | HEX / Base64 / Base32 / URL / 文本互转，严格输入校验 |
| | 密文长度分析 | 依据长度与首字节特征推断算法类型（启发式） |
| | P7 签名数据解析 | PKCS#7 / CMS SignedData 解析、验签、messageDigest 比对、证书导出 |
| 密码算法校验 | 分组密码 | AES / SM4 / DES / 3DES；ECB / CBC / CFB / OFB / CTR / XTS；6 种填充 |
| | 序列算法 | ZUC-128 加解密（ZUC-256 / MAC 明确标注未支持） |
| | GCM 模式 | AES-GCM / SM4-GCM，AAD 与认证标签校验 |
| | 哈希算法 | SM3 / SHA-1 / SHA-2 / SHA-3 / MD5，盐值与 HMAC |
| | MAC 算法 | CBC-MAC / CMAC（AES、SM4）；其它模式标注未支持 |
| | SM2 签名验签 | SM3withSM2，UID 真正参与 ZA，支持 r‖s 与 DER |
| | SM2 加密解密 | C1C3C2 / C1C2C3，C3 校验 |
| | 密钥对生成 | SM2 / RSA-2048/3072/4096，PEM 与 HEX 输出 |
| | RSA 签名验签 | PKCS#1 v1.5 / PSS，区分“签名无效”与“输入错误” |
| 协议分析 | PCAP 加密数据提取 | 纯 Python 解析 pcap/pcapng：TLS/TLCP 握手、套件、证书、加密记录（保留边界）、ESP、IKE 证书 |
| 数字证书 | 证书链验证 | 逐级验签（RSA/ECDSA/SM2）、有效期、CA 约束、pathLen |
| | 证书吊销检查 | 离线 CRL（验签、有效期、issuer 匹配、序列号命中） |
| | ASN.1 证书解析 | TLV 结构树、字段与扩展、SHA-1/SHA-256/SM3 指纹、导出 |
| | CRL 格式校验 | CRL 信息、签名验证、吊销条目 |
| 随机数检测 | GM/T 0005-2021 随机性检测 | 参照 GMT_Randomness_Test 布局：左侧 17 种检测方法勾选、文本/文件输入、α 与模式（20k/1M/100M/自动/自定义）、右侧汇总 + 逐项 P/Q 值、参数与判定明细 |
| 电子签章 | 电子签章校验 | PDF（CMS 与国密电子印章容器）、OFD（Seal.esl + SignedValue + Signature.xml 文件摘要链），多签章分页，三态结论 |

## 技术栈

- **GUI**：PySide6（Qt 6，LGPL）；离屏渲染用于自动化截图回归
- **密码算法**：gmalg（SM2/SM3/SM4/SM9/ZUC，纯 Python）、tongsuopy（SM3/SM4/GCM 的 BabaSSL C 实现）、PyCryptodome（AES/DES/RSA/CMAC）
- **ASN.1 / X.509 / CMS / CRL**：自研 DER 解析层（原因：asn1crypto 1.5.1 无法解析 SM2 证书与含 SM2 证书的 CMS）
- **PDF**：原始字节解析 /ByteRange /Contents（不依赖第三方 PDF 签名库）
- **随机性检测**：按 GM/T 0005-2021 以 numpy 向量化实现；参考 BSD-3 项目 guojuntang/gmt_randomness_test 并保留署名
- **测试**：unittest（108 项），官方向量 + 双实现交叉验证 + 离屏 UI 冒烟

## 免安装分发包

已提供免安装压缩包：`dist/密评工具箱_v2.0.0_免安装.zip`（约 65 MB）。

1. 解压到任意目录（建议短路径，如 `D:\CryptoEval`）；
2. 双击 `密评工具箱.exe` 运行，无需安装、无需管理员权限；
3. 程序未做代码签名，首次运行如遇 SmartScreen 提示，请选择“更多信息 → 仍要运行”。

重新构建（需已安装 PyInstaller）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_portable.ps1
```

## 安装与启动

要求：Windows 10/11，Python 3.11–3.13。

```powershell
cd cryptotoolbox
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe run.py
```

> 若 PyPI 需要代理：先设置 `$env:HTTPS_PROXY='http://127.0.0.1:7897'`（按实际代理地址）。
> 本机开发环境已用 `python -m venv --without-pip --system-site-packages` 创建（因 ensurepip 在此环境受限），并使用 `sitecustomize.py` 修正临时目录权限；正常环境直接 `python -m venv .venv` 即可。

## 界面特性

- 明暗主题切换；默认强调色为 **#5500FF**，设置中可修改并持久化（下次启动保持）
- 窗口按屏幕可用区域自动选择合适大小并居中（避免超出屏幕）
- 点击左上角“密评工具箱”标题随时返回首页；左下角/右下角署名 Draina

## 测试

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -t .
```

- 官方向量：SM3（GB/T 32905）、SM4（GM/T 0002）、SM2（GM/T 0003.5 示例曲线 + 官方曲线，Botan 测试数据）、AES/DES（FIPS/NIST SP 800-38A）、GCM（NIST GCM 规范）、XTS（IEEE P1619/D16）、CMAC（NIST SP 800-38B）、HMAC（RFC 2202/4231）
- 交叉验证：SM2 与 gmalg 互验；SM3/HMAC-SM3 与 tongsuopy 对照；随机性检测与参考实现（guojuntang/gmt_randomness_test）逐项对比 P 值
- 证书/CRL/CMS 样本由 `scripts/make_cert_fixtures.ps1` 用 openssl 生成（RSA/ECDSA/SM2 链、CRL、CMS），PDF/OFD 签章样本由 `tests/support/seal_build.py` 构造
- UI：`tests/test_ui_smoke.py` 离屏构造全部页面；`scripts/screenshots.py` 生成明暗主题截图

## 准确性说明（摘要）


- SM2 签名的用户标识（UID）真正参与 ZA 计算；证书/CMS/PDF 验签时按“签名者证书 Subject DER → 空 → 默认 1234567812345678”依次尝试并**报告实际使用的约定**（不同实现的 SM2 UID 约定不同，本项目不静默通过）
- ECDSA 证书验签使用 DER 编码签名（修复原项目误用 P1363 的问题）
- HMAC-SM3 按 RFC 2104 的 ipad/opad 结构实现（原项目的 H(K‖M) 已修正）
- 流模式（CTR/OFB/CFB）不套分组填充；CTR 支持 16 字节初始计数器
- 结论三态：通过 / 未通过 / 未知；无法验证的项（私有签章容器、未知算法等）绝不会显示为通过

## 已知限制

- ZUC-256、ZUC-MAC：需要 GM/T 0001.1-2021 完整参数，当前版本明确标注未支持
- 在线 OCSP：未提供（离线 CRL 已完整实现）
- MAC：LMAC / CBCR / TrCBC / EMAC / ANSI X9.19 / MacDES 未提供
- 随机性检测：任意长度可用（小样本自动跳过不可用项）；100M 模式因纯 Python 性能原因不启用线性复杂度与 Maurer 通用统计（界面明确标注）；1M 全项检测可能耗时数分钟，可随时取消
- 已支持 GB/T 38540 / GM/T 0031 形态的国密电子印章容器（PDF/OFD）；更私有的封装若无法识别会标注“未知”
- 1M 随机性全套检测包含线性复杂度，单样本约 1 分钟量级；批量检测在后台线程执行并显示进度。任意长度样本的参数为自适应选择，与标准固定参数不完全相同（界面会显示当前长度与可用项）


## 目录结构

```
cryptotoolbox/
├── run.py                      # 入口
├── requirements.txt
├── cryptotoolbox/
│   ├── app.py / theme.py       # 引导与主题
│   ├── core/                   # 纯逻辑层（无 Qt 依赖）
│   │   ├── der.py x509.py cms.py crl.py pkcs7.py cert.py keys.py
│   │   ├── sm2.py sm3?(digest.py) blockcipher.py gcm.py mac.py zuc.py encodings.py
│   │   ├── pcap.py seal.py randomness.py result.py
│   └── ui/                     # 界面层（页面、控件、主题、后台任务）
├── tests/                      # 108 项测试 + 官方向量/证书样本 + 合成 PDF/OFD/PCAP
├── scripts/                    # 截图、证书样本生成、测试脚本
└── docs/accuracy.md            # 算法↔标准↔向量对照与差异说明
```

## 许可与第三方

- 仅供学习交流参考 未经允许禁止二改与商用

