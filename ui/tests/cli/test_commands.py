#
# pytest -v cli/test_commands.py
#
# The commands of opensnitch-cli that act on the database without a daemon,
# driven the way main() drives them: through the parser and the cmd_* function.
#

import json
import time

from google.protobuf import json_format

from opensnitch.cli import db as dbmod, main
from opensnitch.cli.proto import ui_pb2


def run(argv, config):
    args = main.build_parser().parse_args(argv)
    return args.func(args, config)


def a_rule(name, enabled=True):
    rule = ui_pb2.Rule(name=name, enabled=enabled, action="allow", duration="always")
    rule.operator.type = "simple"
    rule.operator.operand = "process.path"
    rule.operator.data = "/usr/bin/curl"
    return rule


def queued(db):
    return [(row["ntf_type"], json.loads(row["rule_json"]))
            for row in db.queued_notifications()]


class TestRule:

    def test_delete_queues_a_delete_for_the_daemon(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "delete", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DELETE_RULE
        assert rule["name"] == "r"
        # the daemon refuses a rule without an operator, even to delete it
        assert rule["operator"]["operand"] == "true"

    def test_disable_sends_the_whole_rule_back(self, db, config):
        """a name alone would make the daemon replace the rule with an empty
        one (notifications.go handleActionEnableRule): the real rule has to
        travel with the request."""
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "disable", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.DISABLE_RULE
        # protobuf's JSON leaves out fields at their default, so a missing
        # "enabled" is false
        assert rule.get("enabled", False) is False
        assert rule["operator"]["data"] == "/usr/bin/curl"
        assert rule["action"] == "allow"

    def test_enable_after_disable(self, db, config):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r", enabled=False)])

        assert run(["rule", "enable", "r"], config) == 0

        [(ntf_type, rule)] = queued(db)
        assert ntf_type == ui_pb2.ENABLE_RULE
        assert rule["enabled"] is True

    def test_enabling_an_enabled_rule_sends_nothing(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.replace_rules("unix:/local", [a_rule("r")])

        assert run(["rule", "enable", "r"], config) == 0
        assert queued(db) == []
        assert "already enabled" in capsys.readouterr().out

    def test_enable_needs_a_rule_it_knows(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")

        assert run(["rule", "enable", "nope"], config) == 1
        assert queued(db) == []
        assert "no rule called 'nope'" in capsys.readouterr().err

    def test_delete_of_an_unknown_rule_is_sent_with_a_note(self, db, config, capsys):
        """the list can be stale; deleting a rule the daemon lacks is harmless."""
        db.node_seen("unix:/local", "h", "1.9.0")

        assert run(["rule", "delete", "nope"], config) == 0
        assert len(queued(db)) == 1
        assert "not among the rules" in capsys.readouterr().err

    def test_with_several_nodes_the_node_must_be_named(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        db.node_seen("ipv4:10.0.0.2", "h2", "1.9.0")
        db.replace_rules("ipv4:10.0.0.2", [a_rule("r")])

        assert run(["rule", "delete", "r"], config) == 1
        assert "--node" in capsys.readouterr().err

        assert run(["rule", "delete", "r", "--node", "ipv4:10.0.0.2"], config) == 0
        [row] = db.queued_notifications()
        assert row["node"] == "ipv4:10.0.0.2"

    def test_an_unknown_node_is_refused(self, db, config, capsys):
        db.node_seen("unix:/local", "h", "1.9.0")
        assert run(["rule", "delete", "r", "--node", "ipv4:9.9.9.9"], config) == 1
        assert "no node called" in capsys.readouterr().err

    def test_nothing_to_send_to_without_a_node(self, db, config, capsys):
        assert run(["rule", "delete", "r"], config) == 1
        assert "no node has connected" in capsys.readouterr().err

