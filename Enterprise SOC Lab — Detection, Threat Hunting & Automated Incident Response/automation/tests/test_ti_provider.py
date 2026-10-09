import os
import unittest

from ti_provider import query_virustotal_ip


class TestTIProvider(unittest.TestCase):

    def test_provider_without_api_key(self):
        os.environ.pop("VT_API_KEY", None)

        result = query_virustotal_ip("192.0.2.50")

        self.assertEqual(
            result["status"],
            "not_configured"
        )

        self.assertEqual(
            result["observable"],
            "192.0.2.50"
        )


if __name__ == "__main__":
    unittest.main()
