# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2016 Valentin Samir
import os
import sqlite3
import tempfile
import time
from unittest import TestCase

from policyd_rate_limit.tests import utils as test_utils


class DaemonTestCase(TestCase):

    def setUp(self):
        self.base_config = dict(
            SOCKET=tempfile.mktemp('.sock'),
            sqlite_config={"database": tempfile.mktemp('.sqlite3')},
            pidfile=tempfile.mktemp('.pid'),
            limit_by_sasl=True,
            limit_by_ip=True,
            limited_networks=["192.168.0.0/16", "ffee::/64"],
            debug=True,
            report=True,
            report_limits=[60, 86400],
            user="root",
            group="root",
            count_mode=0,
        )

    def tearDown(self):
        if os.path.isfile(self.base_config["sqlite_config"]["database"]):
            os.remove(self.base_config["sqlite_config"]["database"])

    def test_main_unix_socket(self):
        with test_utils.lauch(self.base_config) as cfg:
            self.base_test(cfg)

    def test_main_afinet_socket(self):
        self.base_config["SOCKET"] = ["127.0.0.1", 27184]
        with test_utils.lauch(self.base_config) as cfg:
            self.base_test(cfg)

    # travis CI/Github Action has no IPv6 support
    # def test_main_afinet6_socket(self):
    #     self.base_config["SOCKET"] = ["::1", 27184]
    #     with test_utils.lauch(self.base_config) as cfg:
    #         self.base_test(cfg)

    def test_no_debug_no_report(self):
        self.base_config["debug"] = False
        self.base_config["report"] = False
        with test_utils.lauch(self.base_config) as cfg:
            self.base_test(cfg)

    def test_limit(self):
        with test_utils.lauch(self.base_config) as cfg:
            for i in range(10):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
            # the eleventh counted requests should fail
            data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def test_limit_batch(self):
        with test_utils.lauch(self.base_config) as cfg:
            # Send a batch of mails
            for i in range(10):
                data = test_utils.send_policyd_request(
                    cfg["SOCKET"], sasl_username="test", instance="test"
                )
                self.assertEqual(data.strip(), b"action=dunno")
            # the eleventh counted requests should fail and the 10 previous should be discard
            data = test_utils.send_policyd_request(
                cfg["SOCKET"], sasl_username="test", instance="test"
            )
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")
            # The limit should have be reverted (cf instance)
            for i in range(10):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
            # the eleventh counted requests should fail
            data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def test_limit_batch2(self):
        self.base_config["count_mode"] = 1
        with test_utils.lauch(self.base_config) as cfg:
            # Send a batch of mails
            data = test_utils.send_policyd_request(
                cfg["SOCKET"], sasl_username="test", protocol_state="DATA", recipient_count=11
            )
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")
            # The limit should have be reverted (cf instance)
            data = test_utils.send_policyd_request(
                cfg["SOCKET"], sasl_username="test", protocol_state="DATA", recipient_count=10
            )
            self.assertEqual(data.strip(), b"action=dunno")
            # the eleventh counted requests should fail
            data = test_utils.send_policyd_request(
                cfg["SOCKET"], sasl_username="test", protocol_state="DATA", recipient_count=1
            )
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def test_limit_batch3(self):
        self.base_config["count_mode"] = 2
        with test_utils.lauch(self.base_config) as cfg:
            for _ in range(10):
                # a single mail with many recipients
                data = test_utils.send_policyd_request(
                    cfg["SOCKET"], sasl_username="test", protocol_state="DATA", recipient_count=100
                )
                # it should be accepted
                self.assertEqual(data.strip(), b"action=dunno")
            # The 11th mail should be denied
            data = test_utils.send_policyd_request(
                cfg["SOCKET"], sasl_username="test", protocol_state="DATA", recipient_count=1
            )
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def test_slow_connection(self):
        with test_utils.lauch(self.base_config) as cfg:
            with test_utils.sock(cfg["SOCKET"]) as s:
                msg = test_utils.postfix_request(sasl_username="test")
                i = 0
                s.send(msg[i:10])
                i += 10
                # run another request before the previous one is ended
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
                s.send(msg[i:1])
                i += 1
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
                s.send(msg[i:])
                datal = []
                datal.append(s.recv(2))
                # run another request before the previous one is ended
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
                datal.append(s.recv(1024))
                data = b"".join(datal)
                self.assertEqual(data.strip(), b"action=dunno")

    def test_database_unavailable(self):
        # create the database
        with open(self.base_config["sqlite_config"]["database"], 'a'):
            pass
        # make it unavailable
        os.chmod(self.base_config["sqlite_config"]["database"], 0)
        # lauch policyd-rate-limit with the database navailable
        with test_utils.lauch(self.base_config) as cfg:
            # as long as the database is unavailable, all response should be dunno
            for i in range(20):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
            # make the database available, it should be initialized upon the next request
            os.chmod(self.base_config["sqlite_config"]["database"], 0o644)
            # these requests should be counted
            for i in range(10):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
                self.assertEqual(data.strip(), b"action=dunno")
            # the eleventh counted requests should fail
            data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def test_bad_config(self):
        self.base_config["backend"] = 1000
        with test_utils.lauch(self.base_config, get_process=True) as p:
            self.assertEqual(p.wait(timeout=10), 5)

    def test_get_config(self):
        with test_utils.lauch(
            self.base_config,
            get_process=True,
            options=["--get-config", "pidfile"]
        ) as p:
            self.assertEqual(p.wait(timeout=10), 0)
            self.assertEqual(p.stdout.read(), self.base_config["pidfile"].encode())
        with test_utils.lauch(
            self.base_config,
            get_process=True,
            options=["--get-config", "sqlite_config.database"]
        ) as p:
            self.assertEqual(p.wait(timeout=10), 0)
            self.assertEqual(
                p.stdout.read(),
                self.base_config["sqlite_config"]["database"].encode()
            )
        with test_utils.lauch(
            self.base_config,
            get_process=True,
            options=["--get-config", "foo"]
        ) as p:
            self.assertEqual(p.wait(timeout=10), 1)
        with test_utils.lauch(
            None,
            get_process=True,
            options=["--get-config", "pidfile"]
        ) as p:
            self.assertEqual(p.wait(timeout=10), 0)
            self.assertEqual(
                p.stdout.read(),
                b'/var/run/policyd-rate-limit/policyd-rate-limit.pid'
            )

    def test_no_config_file_found(self):
        with test_utils.lauch(None, get_process=True) as p:
            self.assertEqual(p.wait(timeout=10), 5)

    def test_already_running(self):
        with test_utils.lauch(self.base_config, no_coverage=True, get_process=True) as p1:
            pid = p1.pid
            with test_utils.lauch(self.base_config, get_process=True) as p2:
                self.assertEqual(p2.wait(), 3)
        with open(self.base_config["pidfile"], 'w') as f:
            f.write("%s" % pid)
        try:
            with test_utils.lauch(self.base_config, get_process=True) as p:
                pass
            self.assertEqual(p.wait(timeout=10), 0)
            with open(self.base_config["pidfile"], 'w') as f:
                f.write("foo")
            with test_utils.lauch(self.base_config, get_process=True) as p:
                pass
            self.assertEqual(p.wait(timeout=10), 0)
            with open(self.base_config["pidfile"], 'w') as f:
                f.write("")
            os.chmod(self.base_config["pidfile"], 0)
            with test_utils.lauch(self.base_config, get_process=True) as p:
                self.assertEqual(p.wait(timeout=10), 6)
        finally:
            try:
                os.remove(self.base_config["pidfile"])
            except OSError:
                pass

    def test_bad_socket_bind_address(self):
        self.base_config["SOCKET"] = ["toto", 1234]
        with test_utils.lauch(self.base_config, get_process=True, no_wait=True) as p:
            self.assertEqual(p.wait(timeout=10), 4)
        self.base_config["SOCKET"] = ["192.168::1", 1234]
        with test_utils.lauch(self.base_config, get_process=True, no_wait=True) as p:
            self.assertEqual(p.wait(timeout=10), 6)

    def test_clean(self):
        self.base_config["report_to"] = "foo@example.com"
        with test_utils.lauch(self.base_config, options=["--clean"], get_process=True) as p:
            self.assertEqual(p.wait(timeout=10), 0)
        self.base_config["report_only_if_needed"] = False
        self.base_config["smtp_server"] = "localhost"
        with test_utils.lauch(self.base_config, options=["--clean"], get_process=True) as p:
            self.assertEqual(p.wait(timeout=10), 8)

    def limit_report(self):
        """Return the rows of the limit_report table of the test database"""
        db = sqlite3.connect(self.base_config["sqlite_config"]["database"])
        try:
            cur = db.cursor()
            cur.execute("SELECT id, delta, hit, date FROM limit_report")
            return sorted(cur.fetchall())
        finally:
            db.close()

    def test_report_hits_by_day(self):
        with test_utils.lauch(self.base_config) as cfg:
            # the first 10 requests pass, the 2 next hit the 10 mails by minute limit
            for i in range(12):
                test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
        # both hits of the day are aggregated on a single row dated of today
        self.assertEqual(
            self.limit_report(),
            [("test", 60, 2, time.strftime("%Y-%m-%d"))]
        )

    def test_report_add_date_migration(self):
        # build a limit_report table as created by a version without the date column
        db = sqlite3.connect(self.base_config["sqlite_config"]["database"])
        try:
            cur = db.cursor()
            cur.execute(
                "CREATE TABLE limit_report ("
                "id varchar(40) NOT NULL, delta int NOT NULL, hit int NOT NULL DEFAULT 0)"
            )
            cur.execute("CREATE UNIQUE INDEX limit_report_index ON limit_report(id, delta)")
            cur.execute("INSERT INTO limit_report (id, delta, hit) VALUES ('old', 60, 5)")
            db.commit()
        finally:
            db.close()
        with test_utils.lauch(self.base_config) as cfg:
            for i in range(12):
                test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
        # the already recorded hits are kept and dated of today, new hits are recorded as usual
        today = time.strftime("%Y-%m-%d")
        self.assertEqual(
            self.limit_report(),
            [("old", 60, 5, today), ("test", 60, 2, today)]
        )

    def test_clean_retention_days(self):
        self.base_config["retention_days"] = 2
        # a first run to let the daemon create the tables and record a mail of today
        with test_utils.lauch(self.base_config) as cfg:
            test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
        old_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 3 * 86400))
        db = sqlite3.connect(self.base_config["sqlite_config"]["database"])
        try:
            cur = db.cursor()
            cur.execute(
                "INSERT INTO mail_count VALUES ('old', ?, 1, 'instance', 'RCPT')",
                (int(time.time() - 3 * 86400),)
            )
            cur.execute(
                "INSERT INTO limit_report (id, delta, hit, date) VALUES (?, 60, 5, ?)",
                ("old", old_day)
            )
            cur.execute(
                "INSERT INTO limit_report (id, delta, hit, date) VALUES (?, 60, 5, ?)",
                ("recent", time.strftime("%Y-%m-%d"))
            )
            db.commit()
        finally:
            db.close()
        with test_utils.lauch(self.base_config, options=["--clean"], get_process=True) as p:
            self.assertEqual(p.wait(timeout=10), 0)
        # only the records of the last 2 days are kept, in both tables
        db = sqlite3.connect(self.base_config["sqlite_config"]["database"])
        try:
            cur = db.cursor()
            cur.execute("SELECT id FROM mail_count")
            self.assertEqual(cur.fetchall(), [("test",)])
        finally:
            db.close()
        self.assertEqual([row[0] for row in self.limit_report()], ["recent"])

    def test_limits_by_id(self):
        self.base_config["limits_by_id"] = {'foo': [[2, 60]], 'bar': []}
        with test_utils.lauch(self.base_config) as cfg:
            self.base_test(cfg)
            for i in range(20):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="bar")
                self.assertEqual(data.strip(), b"action=dunno")
            for i in range(2):
                data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="foo")
                self.assertEqual(data.strip(), b"action=dunno")
            data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="foo")
            self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")

    def base_test(self, cfg):
        # test limit by sasl username
        for i in range(10):
            data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
            self.assertEqual(data.strip(), b"action=dunno")
        data = test_utils.send_policyd_request(cfg["SOCKET"], sasl_username="test")
        self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")
        # test limit by ip
        for i in range(10):
            data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="192.168.0.1")
            self.assertEqual(data.strip(), b"action=dunno")
        data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="192.168.0.1")
        self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")
        # test limit by ip in ipv6
        for i in range(10):
            data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="ffee::1")
            self.assertEqual(data.strip(), b"action=dunno")
        data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="ffee::1")
        self.assertEqual(data.strip(), b"action=defer_if_permit Rate limit reach, retry later")
        # test limit by ip not limited
        for i in range(10):
            data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="10.0.0.1")
            self.assertEqual(data.strip(), b"action=dunno")
        data = test_utils.send_policyd_request(cfg["SOCKET"], client_address="10.0.0.1")
        self.assertEqual(data.strip(), b"action=dunno")
        # test with bad protocol state
        for i in range(10):
            data = test_utils.send_policyd_request(
                cfg["SOCKET"],
                sasl_username="test",
                protocol_state="VRFY"
            )
            self.assertEqual(data.strip(), b"action=dunno")
        data = test_utils.send_policyd_request(
            cfg["SOCKET"],
            sasl_username="test",
            protocol_state="VRFY"
        )
        self.assertEqual(data.strip(), b"action=dunno")
