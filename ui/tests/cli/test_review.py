#
# pytest -v cli/test_review.py
#

import json

from opensnitch.cli import db as dbmod, review
from opensnitch.cli.proto import ui_pb2


def scripted(answers):
    """feeds the review loop a fixed list of answers."""
    it = iter(answers)

    def read(prompt):
        try:
            return next(it)
        except StopIteration:
            return "q"
    return read


def silent(*args, **kwargs):
    pass


def queue_one(db, connection, provisional="cli-auto-abc"):
    db.record_pending("unix:/local", "sig", connection,
                      {"name": provisional, "action": "allow", "duration": "1h",
                       "expires_in": 3600})
    return db.pending()[0]


def sent_rules(db):
    """the notifications waiting for the service to pick up."""
    out = []
    for row in db.queued_notifications():
        out.append((row["ntf_type"], json.loads(row["rule_json"])))
    return out


class TestReviewLoop:

    def test_accepting_creates_an_allow_rule(self, db, config, connection):
        queue_one(db, connection)
        applied = review.review_loop(db, db.pending(), config,
                                     read=scripted(["y"]), write=silent)

        assert applied == 1
        types = [t for t, _ in sent_rules(db)]
        # the temporary rule is removed first, then the real one is installed
        assert types == [ui_pb2.DELETE_RULE, ui_pb2.CHANGE_RULE]

        _, rule = sent_rules(db)[1]
        assert rule["action"] == "allow"
        assert rule["duration"] == "always"

    def test_n_denies_the_same_match(self, db, config, connection):
        queue_one(db, connection)
        review.review_loop(db, db.pending(), config, read=scripted(["n"]), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["action"] == "deny"

    def test_r_rejects(self, db, config, connection):
        queue_one(db, connection)
        review.review_loop(db, db.pending(), config, read=scripted(["r"]), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["action"] == "reject"

    def test_the_entry_leaves_the_queue(self, db, config, connection):
        queue_one(db, connection)
        review.review_loop(db, db.pending(), config, read=scripted(["y"]), write=silent)
        assert db.pending_count() == 0

    def test_skipping_leaves_it_alone(self, db, config, connection):
        queue_one(db, connection)
        applied = review.review_loop(db, db.pending(), config,
                                     read=scripted(["s"]), write=silent)

        assert applied == 0
        assert db.pending_count() == 1
        assert sent_rules(db) == []

    def test_dropping_creates_no_rule(self, db, config, connection):
        queue_one(db, connection)
        review.review_loop(db, db.pending(), config, read=scripted(["d"]), write=silent)

        assert db.pending_count() == 0
        assert sent_rules(db) == []

    def test_quitting_stops(self, db, config, connection):
        queue_one(db, connection)
        assert review.review_loop(db, db.pending(), config,
                                  read=scripted(["q"]), write=silent) == 0

    def test_empty_answer_does_nothing(self, db, config, connection):
        """like git add -p: no destructive default."""
        queue_one(db, connection)
        review.review_loop(db, db.pending(), config, read=scripted(["", "", "s"]),
                           write=silent)
        assert db.pending_count() == 1

    def test_no_provisional_rule_means_no_delete(self, db, config, connection):
        db.record_pending("unix:/local", "sig", connection, {})
        review.review_loop(db, db.pending(), config, read=scripted(["y"]), write=silent)

        assert [t for t, _ in sent_rules(db)] == [ui_pb2.CHANGE_RULE]


class TestEditing:

    def test_switch_to_the_host_wildcard_and_deny_forever(self, db, config, connection):
        """the case the whole thing exists for: narrow the rule by hand."""
        queue_one(db, connection)

        # e -> match on -> the *.github.com wildcard -> action -> deny -> apply
        answers = ["e", "1", "4", "2", "2", "a"]
        review.review_loop(db, db.pending(), config, read=scripted(answers), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["action"] == "deny"
        assert rule["operator"]["type"] == "regexp"
        assert rule["operator"]["operand"] == "dest.host"
        assert rule["operator"]["data"] == r"^(|.*\.)github\.com$"

    def test_switch_to_the_command_line(self, db, config, connection):
        queue_one(db, connection)
        answers = ["e", "1", "2", "a"]
        review.review_loop(db, db.pending(), config, read=scripted(answers), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["operator"]["operand"] == "process.command"

    def test_change_the_duration(self, db, config, connection):
        queue_one(db, connection)
        # e -> duration -> 1h (entry 5) -> apply
        answers = ["e", "3", "5", "a"]
        review.review_loop(db, db.pending(), config, read=scripted(answers), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["duration"] == "1h"

    def test_adding_a_condition_makes_a_list_rule(self, db, config, connection):
        queue_one(db, connection)
        # e -> also require -> first extra candidate -> apply
        answers = ["e", "5", "1", "a"]
        review.review_loop(db, db.pending(), config, read=scripted(answers), write=silent)

        _, rule = sent_rules(db)[1]
        assert rule["operator"]["type"] == "list"
        assert len(rule["operator"]["list"]) == 2

    def test_cancelling_the_editor_goes_back(self, db, config, connection):
        queue_one(db, connection)
        answers = ["e", "c", "s"]
        applied = review.review_loop(db, db.pending(), config,
                                     read=scripted(answers), write=silent)
        assert applied == 0
        assert db.pending_count() == 1

    def test_a_custom_regexp_go_cannot_compile_is_refused(self, db, config, connection):
        queue_one(db, connection)
        written = []
        # e -> match on -> custom -> regexp / dest.host / lookahead, then give up
        answers = ["e", "1", "c", "regexp", "dest.host", "^(?=x)", "c", "s"]
        review.review_loop(db, db.pending(), config, read=scripted(answers),
                           write=written.append)

        assert any("RE2" in line for line in written)
        assert sent_rules(db) == []


class TestRendering:

    def test_shows_the_process_destination_and_provisional_rule(self, db, config, connection):
        entry = queue_one(db, connection)
        written = []
        review.render_entry(entry, review.entry_connection(entry), 1, 1, written.append)
        text = "\n".join(written)

        assert "/usr/bin/curl" in text
        assert "api.github.com" in text
        assert "443" in text
        assert "cli-auto-abc" in text

    def test_details_include_the_command_line(self, db, config, connection):
        entry = queue_one(db, connection)
        written = []
        review.render_details(entry, review.entry_connection(entry), written.append)
        assert "https://api.github.com/repos" in "\n".join(written)

    def test_the_connection_is_rebuilt_from_the_queue(self, db, config, connection):
        entry = queue_one(db, connection)
        con = review.entry_connection(entry)

        assert con.process_path == connection.process_path
        assert list(con.process_args) == list(connection.process_args)
        assert con.dst_host == connection.dst_host
