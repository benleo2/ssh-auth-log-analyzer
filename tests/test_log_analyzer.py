
import unittest

from log_analyzer import parse_failed_login


class TestLogAnalyzer(unittest.TestCase):

    def test_invalid_user_login(self):
        line = (
            "Sep 5 18:21:32 kali sshd[1234]: "
            "Failed password for invalid user admin "
            "from 192.168.1.50 port 42132 ssh2"
        )

        timestamp, username, ip = parse_failed_login(line)

        self.assertEqual(timestamp, "Sep 5 18:21:32")
        self.assertEqual(username, "admin")
        self.assertEqual(ip, "192.168.1.50")

    def test_normal_failed_login(self):
        line = (
            "Sep 5 18:26:32 kali sshd[1240]: "
            "Failed password for kali "
            "from 10.0.0.25 port 44221 ssh2"
        )

        timestamp, username, ip = parse_failed_login(line)

        self.assertEqual(timestamp, "Sep 5 18:26:32")
        self.assertEqual(username, "kali")
        self.assertEqual(ip, "10.0.0.25")


if __name__ == "__main__":
    unittest.main()
