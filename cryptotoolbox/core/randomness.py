"""GM/T 0005-2021 随机性检测电池。

实现 15 种检测方法对应的独立检测项：
- 20,000 bit 样本：22 个独立检测项
- 1,000,000 bit 样本：27 个独立检测项（含块内最大 0/1 游程、前向/后向累加和、重叠子序列双统计值）

每个检测项按标准给出 P 值与 Q 值：卡方型 Q=P；正态型 Q=erfc(V/√2)/2（V 为带符号统计量）。
判定：单样本 P≥0.01；样本集通过率 ≥98.1%（1000 样本时 ≥981）；Q 均匀性 ≥0.0001。

性能：全部检测以内层循环实现为核心（numpy 向量化），线性复杂度检测使用逐块 Berlekamp-Massey。
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

import numpy as np


# ---------------------------------------------------------------- 分布函数
def _gammaincc(a: float, x: float) -> float:
    """正则化上不完全伽马函数 Q(a,x)（Numerical Recipes gammq 实现）。"""
    if x < 0 or a <= 0:
        raise ValueError("gammaincc 参数非法")
    if x == 0:
        return 1.0
    if x < a + 1:
        return 1.0 - _gser(a, x)
    return _gcf(a, x)


def _gser(a: float, x: float) -> float:
    ITMAX = 500
    EPS = 3e-14
    gln = math.lgamma(a)
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(ITMAX):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * EPS:
            return total * math.exp(-x + a * math.log(x) - gln)
    raise ArithmeticError("gser 未收敛")


def _gcf(a: float, x: float) -> float:
    ITMAX = 500
    EPS = 3e-14
    FPMIN = 1e-300
    gln = math.lgamma(a)
    b = x + 1.0 - a
    c = 1.0 / FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, ITMAX):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < FPMIN:
            d = FPMIN
        c = b + an / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            return math.exp(-x + a * math.log(x) - gln) * h
    raise ArithmeticError("gcf 未收敛")


def _erfc(x: float) -> float:
    return math.erfc(x)


def _phi(x: float) -> float:
    """标准正态累积分布函数 Φ(x)。"""
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


def _normal_p(z: float) -> float:
    return _erfc(abs(z) / math.sqrt(2.0))


def _normal_q(z: float) -> float:
    return _erfc(z / math.sqrt(2.0)) / 2.0


# ---------------------------------------------------------------- 参数
PARAMS_20000 = {
    "length": 20000,
    "fwb_m": 1000,
    "poker_m": (4, 8),
    "serial_m": (3, 5),
    "longest_m": 128,
    "binary_derivative": (3, 7),
    "autocorrelation": (2, 8, 16),
    "approximate_entropy": (2, 5),
}

PARAMS_1000000 = {
    "length": 1000000,
    "fwb_m": 10000,
    "poker_m": (4, 8),
    "serial_m": (3, 5),
    "longest_m": 10000,
    "binary_derivative": (3, 7),
    "autocorrelation": (1, 2, 8, 16),
    "approximate_entropy": (2, 5),
    "linear_complexity_m": (500, 1000),
    "maurer": (7, 1280),
    "matrix_block": 32,
}

LONGEST_RUN_PROBS = {
    8: [0.2148, 0.3672, 0.2305, 0.1875],
    128: [0.1174, 0.2430, 0.2494, 0.1752, 0.1027, 0.1124],
    10000: [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727],
}

MAURER_E_VAR = {
    7: (6.1962507, 3.125),
}

MIN_MAURER_BITS = 387840


def params_for_100m() -> dict:
    """100,000,000 bit 模式参数（参照 GMT_Randomness_Test 的 mode_settings.json）。

    说明：纯 Python 实现的线性复杂度与 Maurer 通用统计在 1 亿 bit 下不可接受地慢，
    因此该模式下不启用（结果页会明确提示未执行），其余检测项按标准参数执行。
    """
    return {
        "length": 100000000,
        "fwb_m": 100000,
        "poker_m": (4, 8),
        "serial_m": (3, 5, 7),
        "longest_m": 10000,
        "binary_derivative": (3, 7, 15),
        "autocorrelation": (2, 8, 16, 32),
        "approximate_entropy": (5, 7),
        "linear_complexity_m": (),
        "maurer": None,
        "matrix_block": 32,
    }


def params_for_mode(mode: str, n: int, custom: dict | None = None) -> dict:
    """按参考工具的模式选择参数：20000 / 1000000 / 100000000 / auto / custom。"""
    if mode == "20000":
        params = dict(PARAMS_20000)
    elif mode == "1000000":
        params = dict(PARAMS_1000000)
    elif mode == "100000000":
        params = params_for_100m()
    elif mode == "custom":
        params = params_for_mode("auto", n)
        if custom:
            if custom.get("m"):
                m = int(custom["m"])
                params["fwb_m"] = m
                if m in (3, 5, 7):
                    params["serial_m"] = (m,)
                params["longest_m"] = m
            if custom.get("k"):
                params["binary_derivative"] = (int(custom["k"]),)
            if custom.get("d"):
                params["autocorrelation"] = (int(custom["d"]),)
            if custom.get("L") and custom.get("Q"):
                params["maurer"] = (int(custom["L"]), int(custom["Q"]))
    else:  # auto
        if n <= 20000:
            params = dict(PARAMS_20000)
        elif n <= 1000000:
            params = dict(PARAMS_1000000)
        else:
            params = params_for_100m()
    params["length"] = n
    return params


def _tests_for_params(params: dict) -> list[tuple[str, str]]:
    base = [
        ("monobit", "单比特频数"), ("fwb", "块内频数"), ("poker", "扑克"),
        ("serial", "重叠子序列"), ("runs", "游程总数"), ("runs_dist", "游程分布"),
        ("longest", "块内最大游程"), ("binary_derivative", "二元推导"),
        ("autocorrelation", "自相关"), ("csum", "累加和"),
        ("approximate_entropy", "近似熵"), ("dft", "离散傅里叶变换"),
    ]
    if params.get("linear_complexity_m"):
        base.append(("linear_complexity", "线性复杂度"))
    if params.get("maurer"):
        base.append(("maurer", "Maurer 通用统计"))
    if params.get("matrix_block"):
        base.append(("matrix", "二元矩阵秩"))
    return base


def params_for_length(n: int) -> dict:
    """按样本长度生成检测参数。标准长度（20k/1M）严格沿用 GM/T 0005-2021 附录 A 参数。"""
    if n == 20000:
        return dict(PARAMS_20000)
    if n == 1000000:
        return dict(PARAMS_1000000)
    if n < 2:
        raise ValueError("样本长度至少 2 bit。")
    params: dict = {"length": n}
    # 块内频数：约 100 个块，块长取 8 的整数倍
    block = max(8, (n // 100) // 8 * 8)
    params["fwb_m"] = min(block, max(8, n // 20))
    # 扑克：模式数足够（每个模式期望出现 ≥5 次）
    poker = []
    for m in (4, 8):
        if n // m >= 5 * (1 << m):
            poker.append(m)
    params["poker_m"] = tuple(poker) if poker else (4,)
    # 重叠子序列：m=3/5
    serial_m = []
    if n >= 128:
        serial_m.append(3)
    if n >= 2048:
        serial_m.append(5)
    params["serial_m"] = tuple(serial_m) if serial_m else (3,)
    # 块内最大游程
    if n < 6272:
        params["longest_m"] = 8
    elif n < 750000:
        params["longest_m"] = 128
    else:
        params["longest_m"] = 10000
    params["binary_derivative"] = (3, 7) if n > 256 else (3,)
    autos = [d for d in (1, 2, 8, 16) if d < n // 2]
    if n < 20000:
        autos = [d for d in (2,) if d < n // 2]
    elif n < 100000:
        autos = [d for d in (2, 8, 16) if d < n // 2]
    params["autocorrelation"] = tuple(autos)
    params["approximate_entropy"] = (2, 5) if n >= 1000 else (2,)
    lc = []
    if n // 500 >= 50:
        lc.append(500)
    if n // 1000 >= 50:
        lc.append(1000)
    params["linear_complexity_m"] = tuple(lc)
    params["maurer"] = (7, 1280) if n >= MIN_MAURER_BITS else None
    params["matrix_block"] = 32 if n // 1024 >= 10 else None
    return params


SIGNIFICANCE = 0.01
MIN_Q = 0.0001
PASS_RATE = 0.981
PASS_COUNT_1000 = 981


@dataclass
class ItemResult:
    key: str
    label: str
    p_values: list[float] = field(default_factory=list)
    q_values: list[float] = field(default_factory=list)
    passed: bool = True
    elapsed_ms: int = 0
    error: str = ""
    skipped: bool = False

    def p_text(self) -> str:
        return " / ".join(f"{p:.6g}" for p in self.p_values)

    def q_text(self) -> str:
        return " / ".join(f"{q:.6g}" for q in self.q_values)


# ---------------------------------------------------------------- 各检测项
def monobit(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    ones = int(bits.sum())
    z = (2 * ones - n) / math.sqrt(n)
    p = _normal_p(z)
    q = _normal_q(z)
    return [ItemResult("monobit", "单比特频数", [p], [q], p >= SIGNIFICANCE)]


def frequency_within_block(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    m = params["fwb_m"]
    blocks = n // m
    if blocks < 1:
        return [ItemResult("fwb", "块内频数", error="样本长度小于块长")]
    pi = bits[: blocks * m].reshape(blocks, m).mean(axis=1)
    chi = 4.0 * m * float(((pi - 0.5) ** 2).sum())
    p = _gammaincc(blocks / 2.0, chi / 2.0)
    return [ItemResult("fwb", "块内频数", [p], [p], p >= SIGNIFICANCE)]


def _pattern_counts(bits: np.ndarray, m: int) -> np.ndarray:
    n = bits.size
    pad = np.concatenate((bits, bits[:m - 1])) if m > 1 else bits
    windows = np.lib.stride_tricks.sliding_window_view(pad, m)
    weights = (1 << np.arange(m - 1, -1, -1, dtype=np.int64))
    values = (windows.astype(np.int64) * weights).sum(axis=1)
    return np.bincount(values, minlength=1 << m)


def poker(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    results = []
    for m in params["poker_m"]:
        k = n // m
        vals = np.concatenate((bits, bits[:n % m]))[: k * m].reshape(k, m)
        weights = (1 << np.arange(m - 1, -1, -1, dtype=np.int64))
        codes = (vals.astype(np.int64) * weights).sum(axis=1)
        counts = np.bincount(codes, minlength=1 << m).astype(np.float64)
        chi = (float(1 << m) / k) * float((counts ** 2).sum()) - k
        p = _gammaincc(((1 << m) - 1) / 2.0, chi / 2.0)
        results.append(ItemResult(f"poker_{m}", f"扑克（m={m}）", [p], [p], p >= SIGNIFICANCE))
    return results


def _psi_sq(bits: np.ndarray, m: int, n: int) -> float:
    counts = _pattern_counts(bits, m).astype(np.float64)
    return (float(1 << m) / n) * float((counts ** 2).sum()) - n


def serial(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    results = []
    for m in params["serial_m"]:
        psi_m = _psi_sq(bits, m, n)
        psi_m1 = _psi_sq(bits, m - 1, n)
        psi_m2 = _psi_sq(bits, m - 2, n) if m >= 2 else 0.0
        grad = psi_m - psi_m1
        grad2 = psi_m - 2 * psi_m1 + psi_m2
        p1 = _gammaincc(float(1 << (m - 2)), grad / 2.0)
        p2 = _gammaincc(float(1 << (m - 3)), grad2 / 2.0) if m >= 3 else 1.0
        results.append(ItemResult(f"serial_{m}_a", f"重叠子序列（m={m}）ψ²", [p1], [p1], p1 >= SIGNIFICANCE))
        results.append(ItemResult(f"serial_{m}_b", f"重叠子序列（m={m}）∇²ψ²", [p2], [p2], p2 >= SIGNIFICANCE))
    return results


def runs(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    ones = int(bits.sum())
    pi = ones / n
    transitions = int(np.count_nonzero(bits[1:] != bits[:-1]))
    v = transitions + 1
    if pi in (0.0, 1.0):
        item = ItemResult("runs", "游程总数", [0.0], [0.0], False)
        item.error = "样本全为 0 或全为 1，游程总数检测必然失败。"
        return [item]
    expected = 2.0 * n * pi * (1 - pi)
    # NIST 归一化：z = (V - 2nπ(1-π)) / (2√n·π(1-π))；p = erfc(|z|/√2)
    z = (v - expected) / (2.0 * math.sqrt(n) * pi * (1 - pi))
    p = _normal_p(z)
    q = _normal_q(z)
    item = ItemResult("runs", "游程总数", [p], [q], p >= SIGNIFICANCE)
    if abs(pi - 0.5) > 2.0 / math.sqrt(n):
        item.error = "样本 0/1 比例偏离 0.5 过多（|π-1/2| > 2/√n），该检验前提不满足。"
    return [item]


def _run_lengths(bits: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """返回 (游程长度数组, 游程取值数组)。"""
    n = bits.size
    diff = np.diff(bits)
    starts = np.flatnonzero(diff != 0) + 1
    boundaries = np.concatenate(([0], starts, [n]))
    lengths = np.diff(boundaries)
    values = bits[boundaries[:-1]]
    return lengths, values


def runs_distribution(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    lengths, values = _run_lengths(bits)
    total_runs = int(lengths.size)
    if total_runs < 2:
        return [ItemResult("runs_dist", "游程分布", error="游程数量过少")]
    # k：使期望频数 e_i ≥ 5
    k = 1
    while (n - k + 3) / (2.0 ** (k + 2)) >= 5.0:
        k += 1
    k = max(1, k - 1)
    buckets = np.minimum(lengths, k) - 1
    idx = values.astype(np.int64) * k + buckets
    counts = np.bincount(idx, minlength=2 * k).astype(np.float64)
    expected = np.zeros(2 * k, dtype=np.float64)
    e = [total_runs / (2.0 ** (i + 1)) for i in range(1, k)]
    e.append(total_runs / (2.0 ** k))
    for v in range(2):
        for i in range(k):
            expected[v * k + i] = e[i]
    if (expected < 5).any():
        return [ItemResult("runs_dist", "游程分布", error="期望频数小于 5，检测不适用")]
    chi = float((((counts - expected) ** 2) / expected).sum())
    p = _gammaincc((2 * k - 2) / 2.0, chi / 2.0)
    return [ItemResult("runs_dist", "游程分布", [p], [p], p >= SIGNIFICANCE)]


def _max_runs(bits: np.ndarray, block_size: int) -> tuple[np.ndarray, np.ndarray]:
    """返回每个块内最大 1 游程与最大 0 游程长度数组。"""
    n = bits.size
    idx = np.arange(n, dtype=np.int64)
    ones = bits.astype(np.int64)
    zeros = 1 - ones
    def max_run(mask: np.ndarray) -> np.ndarray:
        last = np.maximum.accumulate(np.where(mask == 1, idx, -1))
        lengths = idx - last
        return lengths
    run_ones = max_run(ones)
    run_zeros = max_run(zeros)
    blocks = n // block_size
    m1 = run_ones[: blocks * block_size].reshape(blocks, block_size).max(axis=1)
    m0 = run_zeros[: blocks * block_size].reshape(blocks, block_size).max(axis=1)
    return m1, m0


def _longest_run_p(values: np.ndarray, block_size: int, probs: list[float]) -> float:
    k = len(probs) - 1
    if block_size == 8:
        bucket = np.clip(values - 1, 0, k)
    elif block_size == 128:
        bucket = np.clip(values - 4, 0, k)
    elif block_size == 10000:
        bucket = np.clip(values - 10, 0, k)
    else:
        raise ValueError(f"不支持的块长 {block_size}")
    counts = np.bincount(bucket, minlength=k + 1).astype(np.float64)
    blocks = values.size
    expected = np.array(probs, dtype=np.float64) * blocks
    chi = float((((counts - expected) ** 2) / expected).sum())
    return _gammaincc(k / 2.0, chi / 2.0)


def longest_runs_in_a_block(bits: np.ndarray, params: dict) -> list[ItemResult]:
    m = params["longest_m"]
    probs = LONGEST_RUN_PROBS.get(m)
    if probs is None:
        return [ItemResult("longest", "块内最大游程", error=f"缺少块长 {m} 的概率表")]
    max1, max0 = _max_runs(bits, m)
    p1 = _longest_run_p(max1, m, probs)
    p0 = _longest_run_p(max0, m, probs)
    return [
        ItemResult("longest_1", "块内最大 1 游程", [p1], [p1], p1 >= SIGNIFICANCE),
        ItemResult("longest_0", "块内最大 0 游程", [p0], [p0], p0 >= SIGNIFICANCE),
    ]


def binary_derivative(bits: np.ndarray, params: dict) -> list[ItemResult]:
    results = []
    for d in params["binary_derivative"]:
        v = bits.copy()
        for _ in range(d):
            v = np.bitwise_xor(v[:-1], v[1:])
        n2 = v.size
        delta = 2 * int(v.sum()) - n2
        z = delta / math.sqrt(n2)
        p = _normal_p(z)
        q = _normal_q(z)
        results.append(ItemResult(f"bin_der_{d}", f"二元推导（d={d}）", [p], [q], p >= SIGNIFICANCE))
    return results


def autocorrelation(bits: np.ndarray, params: dict) -> list[ItemResult]:
    results = []
    n = bits.size
    for d in params["autocorrelation"]:
        m = n - d
        delta = int(np.count_nonzero(bits[:m] != bits[d:]))
        z = (2 * delta - m) / math.sqrt(m)
        p = _normal_p(z)
        q = _normal_q(z)
        results.append(ItemResult(f"autocorr_{d}", f"自相关（k={d}）", [p], [q], p >= SIGNIFICANCE))
    return results


def _csum_p(s: np.ndarray) -> float:
    n = s.size
    z = float(np.max(np.abs(s)))
    if z == 0:
        return 1.0
    sum_a = 0.0
    start_k = int(math.floor((-n / z + 1) / 4))
    end_k = int(math.floor((n / z - 1) / 4))
    for k in range(start_k, end_k + 1):
        sum_a += _phi((4 * k + 1) * z / math.sqrt(n)) - _phi((4 * k - 1) * z / math.sqrt(n))
    sum_b = 0.0
    start_k = int(math.floor((-n / z - 3) / 4))
    end_k = int(math.floor((n / z - 1) / 4))
    for k in range(start_k, end_k + 1):
        sum_b += _phi((4 * k + 3) * z / math.sqrt(n)) - _phi((4 * k + 1) * z / math.sqrt(n))
    return max(0.0, min(1.0, 1.0 - sum_a + sum_b))


def cumulative_sums(bits: np.ndarray, params: dict) -> list[ItemResult]:
    s = np.cumsum(2 * bits.astype(np.int64) - 1)
    pf = _csum_p(s)
    pb = _csum_p(np.cumsum(2 * bits[::-1].astype(np.int64) - 1))
    return [
        ItemResult("csum_fwd", "累加和（前向）", [pf], [pf], pf >= SIGNIFICANCE),
        ItemResult("csum_bwd", "累加和（后向）", [pb], [pb], pb >= SIGNIFICANCE),
    ]


def approximate_entropy(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    results = []
    for m in params["approximate_entropy"]:
        def phi(block_len: int) -> float:
            counts = _pattern_counts(bits, block_len).astype(np.float64)
            c = counts / n
            positive = c[c > 0]
            return float((positive * np.log(positive)).sum())
        phi_m = phi(m)
        phi_m1 = phi(m + 1)
        chi = 2.0 * n * (math.log(2.0) - (phi_m - phi_m1))
        p = _gammaincc(float(1 << (m - 1)), chi / 2.0)
        results.append(ItemResult(f"ae_{m}", f"近似熵（m={m}）", [p], [p], p >= SIGNIFICANCE))
    return results


def discrete_fourier_transform(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    d = bits.astype(np.float64) * 2.0 - 1.0
    magnitudes = np.abs(np.fft.fft(d)[: n // 2])
    threshold = math.sqrt(2.995732274 * n)
    n1 = float(np.count_nonzero(magnitudes < threshold))
    n0 = 0.95 * n / 2.0
    stat = (n1 - n0) / math.sqrt((n / 3.8) * 0.95 * 0.05)
    p = _normal_p(stat)
    q = _normal_q(stat)
    return [ItemResult("dft", "离散傅里叶变换", [p], [q], p >= SIGNIFICANCE)]


def linear_complexity(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    results = []
    for m in params["linear_complexity_m"]:
        blocks = n // m
        if blocks < 1:
            results.append(ItemResult(f"lc_{m}", f"线性复杂度（M={m}）", error="样本长度小于块长"))
            continue
        nu = np.empty(blocks, dtype=np.int64)
        for i in range(blocks):
            block = bits[i * m:(i + 1) * m]
            nu[i] = _berlekamp_massey_length(block)
        mu = m / 2.0 + (9.0 + (-1) ** (m + 1)) / 36.0 - (m / 3.0 + 2.0 / 9.0) / (2.0 ** m)
        t = ((-1) ** m) * (nu - mu) + 2.0 / 9.0
        bins = np.array([-np.inf, -2.5, -1.5, -0.5, 0.5, 1.5, 2.5, np.inf])
        counts = np.histogram(t, bins=bins)[0].astype(np.float64)
        probs = np.array([1 / 96, 3 / 96, 12 / 96, 48 / 96, 24 / 96, 6 / 96, 2 / 96])
        expected = probs * blocks
        chi = float((((counts - expected) ** 2) / expected).sum())
        p = _gammaincc(3.0, chi / 2.0)
        results.append(ItemResult(f"lc_{m}", f"线性复杂度（M={m}）", [p], [p], p >= SIGNIFICANCE))
    return results


def _berlekamp_massey_length(bits: np.ndarray) -> int:
    n = bits.size
    s = np.asarray(bits, dtype=np.int64)
    c = np.zeros(n + 1, dtype=np.int64)
    b = np.zeros(n + 1, dtype=np.int64)
    c[0] = b[0] = 1
    l = 0
    m = -1
    for i in range(n):
        # discrepancy
        d = s[i]
        for j in range(1, l + 1):
            d ^= int(c[j] & s[i - j])
        if d:
            t = c.copy()
            shift = i - m
            for j in range(0, n + 1 - shift):
                if b[j]:
                    c[j + shift] ^= 1
            if 2 * l <= i:
                l = i + 1 - l
                b = t
                m = i
    return l


def maurers_universal(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    maurer = params.get("maurer")
    if not maurer:
        return [ItemResult("maurer", "Maurer 通用统计", skipped=True, error="样本长度不足，已跳过 Maurer 通用统计")]
    L, Q = maurer
    blocks = n // L
    if blocks <= Q:
        return [ItemResult("maurer", "Maurer 通用统计", error="样本长度不足（Q·L 大于样本）")]
    values = np.zeros(blocks, dtype=np.int64)
    window = np.ones(L, dtype=np.int64) << np.arange(L - 1, -1, -1)
    arr = bits[: blocks * L].reshape(blocks, L).astype(np.int64)
    values = (arr * window).sum(axis=1)
    last = {}
    total = 0.0
    k = blocks - Q
    for i in range(blocks):
        v = int(values[i])
        if i >= Q:
            last_seen = last.get(v)
            distance = i - last_seen if last_seen is not None else i + 1
            total += math.log2(distance)
        last[v] = i
    fn = total / k
    e, var = MAURER_E_VAR[L]
    c = 0.7 - 0.8 / L + (4.0 + 32.0 / L) * (k ** (-3.0 / L)) / 15.0
    sigma = c * math.sqrt(var / k)
    z = (fn - e) / sigma if sigma else 0.0
    p = _normal_p(z)
    q = _normal_q(z)
    return [ItemResult("maurer", "Maurer 通用统计", [p], [q], p >= SIGNIFICANCE)]


def binary_matrix_rank(bits: np.ndarray, params: dict) -> list[ItemResult]:
    n = bits.size
    m = params.get("matrix_block")
    if not m:
        return [ItemResult("matrix", "二元矩阵秩", skipped=True, error="样本长度不足，已跳过二元矩阵秩检测")]
    block_len = m * m
    blocks = n // block_len
    if blocks < 1:
        return [ItemResult("matrix", "二元矩阵秩", error="样本长度不足一个矩阵块")]
    full = 0
    minus_one = 0
    rest = 0
    for i in range(blocks):
        block = bits[i * block_len:(i + 1) * block_len].reshape(m, m)
        rank = _gf2_rank(block)
        if rank == m:
            full += 1
        elif rank == m - 1:
            minus_one += 1
        else:
            rest += 1
    p_full = round(_matrix_prob(m, m), 4)
    p_minus = round(_matrix_prob(m, m - 1), 4)
    p_rest = 1.0 - p_full - p_minus
    probs = np.array([p_rest, p_minus, p_full])
    counts = np.array([rest, minus_one, full], dtype=np.float64)
    expected = probs * blocks
    chi = float((((counts - expected) ** 2) / expected).sum())
    p = math.exp(-chi / 2.0)
    return [ItemResult("matrix", "二元矩阵秩", [p], [p], p >= SIGNIFICANCE)]


def _matrix_prob(m: int, r: int) -> float:
    prod = 1.0
    for i in range(0, r):
        prod *= (1.0 - 2.0 ** (i - m))
    return (2.0 ** (r * (2 * m - r) - m * m)) * prod


def _gf2_rank(block: np.ndarray) -> int:
    m = block.shape[0]
    rows = [int("".join("1" if b else "0" for b in row), 2) for row in block]
    rank = 0
    for col in range(m - 1, -1, -1):
        pivot = None
        for i in range(rank, m):
            if rows[i] & (1 << col):
                pivot = i
                break
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(m):
            if i != rank and (rows[i] & (1 << col)):
                rows[i] ^= rows[rank]
        rank += 1
    return rank


# ---------------------------------------------------------------- 调度
def _tests_for(length: int) -> list[tuple[str, str]]:
    params = params_for_length(length)
    base = [
        ("monobit", "单比特频数"),
        ("fwb", "块内频数"),
        ("poker", "扑克"),
        ("serial", "重叠子序列"),
        ("runs", "游程总数"),
        ("runs_dist", "游程分布"),
        ("longest", "块内最大游程"),
        ("binary_derivative", "二元推导"),
        ("autocorrelation", "自相关"),
        ("csum", "累加和"),
        ("approximate_entropy", "近似熵"),
        ("dft", "离散傅里叶变换"),
    ]
    base += [
        ("linear_complexity", "线性复杂度"),
        ("maurer", "Maurer 通用统计"),
        ("matrix", "二元矩阵秩"),
    ]
    return base


def item_labels(length: int) -> dict[str, str]:
    params = params_for_length(length)
    labels = {"monobit": "单比特频数", "fwb": "块内频数", "runs": "游程总数",
              "runs_dist": "游程分布", "dft": "离散傅里叶变换"}
    labels["maurer"] = "Maurer 通用统计"
    labels["matrix"] = "二元矩阵秩"
    for m in params["poker_m"]:
        labels[f"poker_{m}"] = f"扑克（m={m}）"
    for m in params["serial_m"]:
        labels[f"serial_{m}_a"] = f"重叠子序列（m={m}）ψ²"
        labels[f"serial_{m}_b"] = f"重叠子序列（m={m}）∇²ψ²"
    labels["longest_1"] = "块内最大 1 游程"
    labels["longest_0"] = "块内最大 0 游程"
    for d in params["binary_derivative"]:
        labels[f"bin_der_{d}"] = f"二元推导（d={d}）"
    for d in params["autocorrelation"]:
        labels[f"autocorr_{d}"] = f"自相关（k={d}）"
    labels["csum_fwd"] = "累加和（前向）"
    labels["csum_bwd"] = "累加和（后向）"
    for m in params["approximate_entropy"]:
        labels[f"ae_{m}"] = f"近似熵（m={m}）"
    for m in (500, 1000):
        labels[f"lc_{m}"] = f"线性复杂度（M={m}）"
    return labels


def run_all(bits: np.ndarray, length: int, only: list[str] | None = None,
            progress=None, cancel=None, params: dict | None = None) -> list[ItemResult]:
    """运行指定长度的全套检测。only 为父项 key 列表（如 ["monobit", "poker"]）。"""
    explicit_params = params is not None
    if params is None:
        params = params_for_length(length)
    bits = np.asarray(bits, dtype=np.uint8)
    if bits.size != length:
        raise ValueError(f"样本长度应为 {length} bit，实际 {bits.size} bit。")

    funcs = {
        "monobit": monobit,
        "fwb": frequency_within_block,
        "poker": poker,
        "serial": serial,
        "runs": runs,
        "runs_dist": runs_distribution,
        "longest": longest_runs_in_a_block,
        "binary_derivative": binary_derivative,
        "autocorrelation": autocorrelation,
        "csum": cumulative_sums,
        "approximate_entropy": approximate_entropy,
        "dft": discrete_fourier_transform,
        "linear_complexity": linear_complexity,
        "maurer": maurers_universal,
        "matrix": binary_matrix_rank,
    }
    tests = _tests_for_params(params) if explicit_params else _tests_for(length)
    if only:
        tests = [(key, label) for key, label in tests if key in only]
    results: list[ItemResult] = []
    minimum = {
        "monobit": 2, "fwb": 16, "poker": 320, "serial": 128, "runs": 16,
        "runs_dist": 100, "longest": 64, "binary_derivative": 8, "autocorrelation": 16,
        "csum": 2, "approximate_entropy": 64, "dft": 16,
        "linear_complexity": 500 * 50, "maurer": MIN_MAURER_BITS, "matrix": 1024 * 10,
    }
    for index, (key, _label) in enumerate(tests):
        if cancel is not None and cancel.is_set():
            break
        if progress:
            progress(index, len(tests), key)
        started = time.time()
        if length < minimum.get(key, 2):
            if key == "linear_complexity":
                items = [
                    ItemResult(f"lc_{m}", f"线性复杂度（M={m}）", skipped=True,
                               error=f"样本长度不足（至少 {minimum[key]:,} bit），已跳过")
                    for m in (500, 1000)
                ]
            else:
                items = [ItemResult(key, item_labels(length).get(key, key), skipped=True,
                                    error=f"样本长度不足（至少 {minimum[key]:,} bit），已跳过")]
        else:
            try:
                items = funcs[key](bits, params)
            except Exception as exc:  # noqa: BLE001 - 单项失败不影响其它项
                items = [ItemResult(key, item_labels(length).get(key, key), error=str(exc))]
        elapsed = int((time.time() - started) * 1000)
        for item in items:
            item.elapsed_ms = elapsed
            results.append(item)
    if progress:
        progress(len(tests), len(tests), "完成")
    return results
