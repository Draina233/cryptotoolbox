# 算法准确性说明

本文记录各算法的实现来源、验证方式与已知差异。测试命令：

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -t .
```

## 1. 对称密码与哈希

| 算法 | 实现 | 验证向量 | 结果 |
|---|---|---|---|
| SM3 | 纯 Python 实现（GB/T 32905 结构）+ tongsuopy C 实现对照 | "abc"、"abcd"×16 等（GB/T 32905-2016） | 一致 |
| HMAC-SM3 | RFC 2104 ipad/opad（hashlib 兼容 SM3） | 结构推导 + tongsuopy 独立计算 | 一致（非 H(K‖M)） |
| SM4 | tongsuopy（BabaSSL）ECB/CBC/CFB/OFB/CTR | GM/T 0002-2012 标准向量（ECB） | 一致 |
| AES / DES / 3DES | PyCryptodome | FIPS-197、NIST SP 800-38A 附录 F | 一致 |
| AES-CTR | PyCryptodome Counter(128, initial_value) | NIST SP 800-38A F.5.1（16 字节 IV） | 一致 |
| AES-XTS | 自研 IEEE 1619 实现（PyCryptodome 3.20 无 XTS） | IEEE P1619/D16 Annex B 向量 0/1/2 | 一致 |
| GCM | AES-GCM：PyCryptodome；SM4-GCM：tongsuopy | NIST GCM 规范 test case 1/2/3/4/7/8/9/14/16 | 一致 |
| CMAC | 自研（SP 800-38B 子密钥 + 10* 填充） | NIST SP 800-38B 示例（0/16/40/64 字节） | 一致 |
| CBC-MAC | 零 IV CBC 取末块（对齐时无填充） | SP 800-38A F.2.1 单块向量 | 一致 |

差异与约定：

- 流模式（CTR/OFB/CFB）不套分组填充；若选择填充会提示“流模式忽略填充”。
- XTS 仅支持 AES（SM4 无标准 XTS 模式）；IV 为 16 字节 tweak 输入（数据单元号小端）。
- CBC-MAC 在数据长度为分组整数倍时不做填充（与标准向量语义一致）。

## 2. SM2

| 项目 | 实现 | 验证 |
|---|---|---|
| 曲线运算 | 自研（GB/T 32918.5-2017 参数） | 公钥派生、点乘、签名/验签/加解密往返 |
| 签名/验签 | 自研（标准公式，支持自定义 UID） | GM/T 0003.5-2012 附录 A 示例曲线向量（r/s 完全匹配）；官方曲线向量（Botan）；与 gmalg 互验 |
| ZA / e 值 | 自研 SM3 实现 | 示例曲线 e=B524F552… 完全匹配 |
| 加解密 | 自研（KDF + C3 校验） | 往返 + 篡改检测 + C1C2C3/C1C3C2 双格式 |
| 签名格式 | r‖s ↔ DER 互转 | 双向一致 |

**UID 约定**：不同实现的 SM2 用户标识约定不同（签名者证书 Subject DER / 默认 1234567812345678 / 空）。
本项目在证书链、CMS、PDF/OFD 验签时依次尝试三种约定，并**报告实际使用的约定**；
全部失败才判定验签失败，不会静默通过。测试中使用 openssl 3.5 生成的 SM2 证书（空 ID）验证了该行为。

## 3. 证书 / CMS / CRL

| 能力 | 实现 | 验证 |
|---|---|---|
| X.509 解析 | 自研 DER 解析（支持未知曲线 OID，含 SM2） | openssl 生成 RSA/ECDSA/SM2 证书；字段/扩展解析对照 |
| 证书链验签 | RSA PKCS#1 v1.5、RSA-PSS、ECDSA（DER）、SM2withSM3 | 三级 RSA 链、ECDSA 链、SM2 链；错误 CA/非 CA 拒绝 |
| 链规则 | 有效期、basicConstraints CA、keyUsage keyCertSign、pathLen | 非 CA 证书签发场景被拒绝 |
| CMS 解析/验签 | 自研 CMS；SignerInfo 按 issuer+serial 匹配证书 | RSA（attached/detached）、ECDSA、SM2 CMS 全部通过；篡改内容 messageDigest 失败 |
| CRL | 自研解析（PEM/DER），验签 + 有效期 + issuer 匹配 + 序列号命中 | openssl 生成 CRL；签名验证通过；空吊销列表 |

说明：

- CRL 结论仅在“CRL 由证书 Issuer 签发、签名有效、未过期”时可信，页面会逐项列出。
- 在线 OCSP 未提供；页面明确提示使用离线 CRL 或厂商平台。
- 私有签章容器（如 GM.PkiLite）无法通用验签时返回“未知”，绝不假通过。

## 4. 电子签章（PDF / OFD）

- PDF：标准 CMS（按 SignerInfo issuer+serial 匹配证书、验签、messageDigest）与**国密电子印章容器**
  （SEQUENCE{印章信息/时间/内嵌 SM3 摘要/证书/算法, 签名值}）：签名覆盖内层结构，内嵌摘要与 ByteRange 覆盖内容的 SM3 比对；
  `/Contents` 同时支持 `<hex>` 与 `(literal)` 两种 PDF 字符串，并允许结尾定界符计入签名范围的生成器。
  已用用户提供的真实 PDF 样章（SM3withSM2、国密容器）验证通过。
- OFD：解析 GM/T 0031 形态的 `Seal.esl`（印章信息 + 证书 OCTET STRING + SM3withSM2 签名）与 `SignedValue.dat`
  （签章数据 + 证书 + 签名 + 内嵌 Signature.xml 的 SM3），并校验 `Signature.xml` 中每个引用文件
  CheckValue（SM3 Base64）与 ZIP 内实际文件一致；已用用户提供的真实 OFD 样章验证通过（11/11 文件摘要一致）。
- 结构无法识别时返回“未知”并给出人工复核建议。

## 5. PCAP

- 纯 Python 解析 pcap / pcapng（Ethernet、SLL、SLL2、raw IP、loopback、VLAN）。
- TCP 按序号重组：遇到未捕获缺口时**切分为独立连续段**分别解析（避免零填充破坏 TLS 记录边界）。
- TLS/TLCP 记录：ClientHello（SNI、版本、套件全列表）、ServerHello（选择套件）、Certificate（DER 提取）、
  application data（保留每条记录边界）；ESP（SPI/序列/密文）；IKE UDP 载荷证书扫描（严格 TLV 边界）。
- 测试：合成 pcap/pcapng（含 TLS ClientHello/ServerHello/Certificate、同段多记录、ESP、IKE 证书），断言记录边界与证书提取。

## 6. GM/T 0005-2021 随机性检测

界面按参考工具 GMT_Randomness_Test 组织：左侧检测方法勾选、中间输入/α/模式（20k/1M/100M/自动/自定义参数 m/k/d/L/Q）、
右侧结果汇总（输入长度、耗时、通过/失败/错误/跳过）与逐项明细（P 值、Q 值、参数、说明）。
100M 模式沿用参考工具的 m=100000、serial 3/5/7 等参数，但线性复杂度与 Maurer 通用统计因纯 Python 实现耗时过长不启用（结果中标注“跳过”）。

实现 15 种方法，按标准拆分为独立检测项：

- 20,000 bit：22 项
- 1,000,000 bit：27 项
- 任意自定义长度：按样本长度自适应选择参数与可用检测项（界面显示当前可用项）

判定口径：

- 单样本 P ≥ 0.01；
- 样本通过率：1000 样本时 ≥981，其它样本数 ≥98.1%；
- 样本分布均匀性（Q 值直方图，10 箱，df=9）≥ 0.0001（样本数 ≥10 时计算）；
- 卡方型检测项 Q=P；正态型检测项 Q=erfc(V/√2)/2（V 为带符号统计量）。

与参考实现（guojuntang/gmt_randomness_test）交叉验证的检测项：单比特频数、块内频数、扑克、重叠子序列
（双统计值）、游程总数、累加和（前向/后向）、二元推导、自相关、近似熵、DFT —— P 值一致（1e-9）。

需注意的实现细节：

- **离散傅里叶检测**：分母采用 GM/T 0005-2021 的 n/3.8 系数（2012 版与 NIST 为 n/4），与参考实现一致。
- **块内最大游程**：M=128 与 M=10000 的概率表分别采用标准值（M=10000 使用 2021 版更新后的 π 值）。
- **游程分布**：k 按期望频数 e_i≥5 取 9（20k）与 15（1M），期望值按实际游程总数修正（2021 版修订方法）。
- **线性复杂度**：Berlekamp-Massey 逐块实现，π 分布与 df=6 按标准；1M 单样本耗时约 1 分钟量级。
- 矩阵秩检测使用输入块副本，不修改原始样本（修复参考实现的就地修改缺陷）。
- 参考实现中近似熵公式的 `log(c/10)` 因 Σc=1 在数学上抵消，本项目直接使用标准形式。

## 7. 已知限制

- ZUC-256 / ZUC-MAC、在线 OCSP、EMAC/ANSI X9.19/LMAC/CBCR/TrCBC、100M bit 随机性样本档：未提供（界面明确标注）。
- PDF 签章仅支持标准 CMS/PKCS#7 与可识别的私有容器证书提取；不承诺对全部国密私有容器完成验签。
- SM2 证书的 UID 约定需要与签发方确认；本项目按候选约定验证并报告实际匹配项。
