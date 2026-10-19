import unittest
from cryptotoolbox.core import score


class ScoreTests(unittest.TestCase):
    def _fill(self, level, value):
        layers = score.layer_items(level)
        return [{i: value for i in range(len(layer["items"]))} for layer in layers]

    def test_all_full_total_100(self):
        result = score.compute("2", self._fill("2", 1.0))
        self.assertEqual(result["status"], "ok")
        self.assertAlmostEqual(result["total"], 100.0, places=4)

    def test_tech_half_mgmt_full(self):
        scores = self._fill("3", 1.0)
        for index in range(4):
            for key in scores[index]:
                scores[index][key] = 0.5
        result = score.compute("3", scores)
        self.assertAlmostEqual(result["technical"], 0.5, places=4)
        self.assertAlmostEqual(result["management"], 1.0, places=4)
        self.assertAlmostEqual(result["total"], 65.0, places=4)

    def test_layer_not_applicable(self):
        status, value = score.layer_score(score.layer_items("2")[0]["items"], {})
        self.assertEqual(status, "不适用")
        self.assertIsNone(value)

    def test_invalid_score(self):
        status, value = score.layer_score(score.layer_items("2")[0]["items"], {0: 1.5})
        self.assertEqual(status, "参数错误")

    def test_weights_match_reference(self):
        layers = score.layer_items("2")
        self.assertEqual([len(layer["items"]) for layer in layers], [2, 4, 3, 6, 3, 4, 4, 1])
        self.assertAlmostEqual(layers[0]["items"][0]["weight"], 0.7)
        self.assertAlmostEqual(layers[0]["items"][1]["weight"], 0.4)
        self.assertEqual([t["weight"] for t in score.LEVELS["3"]["total"]], [10, 20, 10, 30, 8, 8, 8, 6])
        self.assertEqual(score.LEVELS["4"]["coef"], [0.7, 0.3])


if __name__ == "__main__":
    unittest.main()
