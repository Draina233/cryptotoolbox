"""GM/T 0005-2021 随机性检测测试。"""
from __future__ import annotations

import math
import unittest

import numpy as np

from cryptotoolbox.core import randomness


def sample_bits(n: int, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.integers(0, 2, size=n, dtype=np.uint8)


class BatteryStructureTests(unittest.TestCase):
    def test_item_counts(self):
        labels20 = randomness.item_labels(20000)
        labels1m = randomness.item_labels(1000000)
        # 20k：18 个父项 → 22 个独立检测项（重叠子序列 2×2、最大游程 2、累加和 2）
        self.assertEqual(len(labels20), 26)
        # 1M：27 个独立检测项（增加线性复杂度 2、Maurer、矩阵秩）
        self.assertEqual(len(labels1m), 27)
        self.assertIn("longest_0", labels1m)
        self.assertIn("csum_bwd", labels1m)
        self.assertIn("lc_1000", labels1m)

    def test_unsupported_length(self):
        with self.assertRaises(ValueError):
            randomness.run_all(sample_bits(1), 1)


class BatteryRunTests(unittest.TestCase):
    def test_random_20k_no_errors(self):
        bits = sample_bits(20000)
        results = randomness.run_all(bits, 20000)
        self.assertEqual(len(results), 26)
        for item in results:
            if item.skipped:
                continue
            self.assertEqual(item.error, "", f"{item.key}: {item.error}")
            for p in item.p_values:
                self.assertTrue(0.0 <= p <= 1.0, f"{item.key} p={p}")
            for q in item.q_values:
                self.assertTrue(0.0 <= q <= 1.0, f"{item.key} q={q}")

    def test_biased_sample_rejected(self):
        zeros = np.zeros(20000, dtype=np.uint8)
        results = {item.key: item for item in randomness.run_all(zeros, 20000)}
        self.assertFalse(results["monobit"].passed)
        self.assertFalse(results["runs"].passed)
        self.assertFalse(results["csum_fwd"].passed)

    def test_monobit_formula(self):
        bits = np.array([1] * 9500 + [0] * 10500, dtype=np.uint8)
        results = randomness.run_all(bits, 20000, only=["monobit"])
        z = (9500 - 10500) / math.sqrt(20000)
        expected_p = math.erfc(abs(z) / math.sqrt(2))
        expected_q = math.erfc(z / math.sqrt(2)) / 2
        self.assertAlmostEqual(results[0].p_values[0], expected_p, places=12)
        self.assertAlmostEqual(results[0].q_values[0], expected_q, places=12)

    def test_1m_subset(self):
        bits = sample_bits(1000000, seed=7)
        subset = ["monobit", "fwb", "poker", "serial", "runs", "runs_dist", "longest",
                  "binary_derivative", "autocorrelation", "csum", "approximate_entropy",
                  "dft", "maurer", "matrix"]
        results = randomness.run_all(bits, 1000000, only=subset)
        for item in results:
            self.assertEqual(item.error, "", f"{item.key}: {item.error}")
        self.assertEqual(len(results), 25)  # 27 - 2 个线性复杂度项

    def test_linear_complexity(self):
        bits = sample_bits(100000, seed=3)
        results = randomness.linear_complexity(bits, {"linear_complexity_m": (500, 1000)} if False else {"linear_complexity_m": (500,)})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].error, "")
        self.assertGreater(results[0].p_values[0], 0.0)

    def test_berlekamp_massey(self):
        zeros = np.zeros(1000, dtype=np.uint8)
        self.assertEqual(randomness._berlekamp_massey_length(zeros), 0)
        bits = np.array([1] * 1000, dtype=np.uint8)
        self.assertEqual(randomness._berlekamp_massey_length(bits), 1)  # 全 1 序列的 LFSR 为 x+1
        # 周期序列 1010... 的线性复杂度为 2
        periodic = (np.arange(1000) % 2).astype(np.uint8)
        self.assertEqual(randomness._berlekamp_massey_length(periodic), 2)

    def test_cancel(self):
        import threading

        event = threading.Event()
        event.set()
        results = randomness.run_all(sample_bits(20000), 20000, cancel=event)
        self.assertEqual(results, [])


class CrossCheckTests(unittest.TestCase):
    """与参考实现（guojuntang/gmt_randomness_test，BSD-3）交叉验证 p 值。"""

    @classmethod
    def setUpClass(cls):
        import sys

        project = r"C:\Users\yuanzhe\PycharmProjects\PythonProject1"
        if project not in sys.path:
            sys.path.insert(0, project)
        try:
            from gmt_random_test.config import GMT_20000  # noqa: F401

            cls.available = True
        except Exception:  # noqa: BLE001
            cls.available = False

    def _reference(self, bits: np.ndarray) -> dict:
        from gmt_random_test.config import GMT_20000

        out = {}
        for key in ("monobit", "frequency_within_block", "poker_4", "poker_8",
                    "serial_3", "serial_5", "runs", "cumulative_sums",
                    "binary_derivative_3", "autocorrelation_2", "approximate_entropy_2",
                    "discrete_fourier_transform"):
            result, _ = GMT_20000[key].run(bits)
            out[key] = [float(x) for x in result.score]
        return out

    def test_cross_check_p_values(self):
        if not self.available:
            self.skipTest("未找到参考实现 gmt_random_test")
        bits = sample_bits(20000, seed=11)
        ours = {item.key: item.p_values for item in randomness.run_all(bits, 20000)}
        ref = self._reference(bits)
        mapping = {
            "monobit": "monobit",
            "fwb": "frequency_within_block",
            "poker_4": "poker_4",
            "poker_8": "poker_8",
            "runs": "runs",
            "dft": "discrete_fourier_transform",
        }
        for ours_key, ref_key in mapping.items():
            self.assertAlmostEqual(ours[ours_key][0], ref[ref_key][0], places=9,
                                   msg=f"{ours_key} 与参考实现不一致")
        # 重叠子序列：参考实现 score=[p1, p2]
        self.assertAlmostEqual(ours["serial_3_a"][0], ref["serial_3"][0], places=9)
        self.assertAlmostEqual(ours["serial_3_b"][0], ref["serial_3"][1], places=9)
        self.assertAlmostEqual(ours["serial_5_a"][0], ref["serial_5"][0], places=9)
        self.assertAlmostEqual(ours["serial_5_b"][0], ref["serial_5"][1], places=9)
        # 累加和：参考实现 score=[前向, 后向]
        self.assertAlmostEqual(ours["csum_fwd"][0], ref["cumulative_sums"][0], places=9)
        self.assertAlmostEqual(ours["csum_bwd"][0], ref["cumulative_sums"][1], places=9)
        # 二元推导 / 自相关 / 近似熵
        self.assertAlmostEqual(ours["bin_der_3"][0], ref["binary_derivative_3"][0], places=9)
        self.assertAlmostEqual(ours["autocorr_2"][0], ref["autocorrelation_2"][0], places=9)
        self.assertAlmostEqual(ours["ae_2"][0], ref["approximate_entropy_2"][0], places=9)


if __name__ == "__main__":
    unittest.main(verbosity=2)


