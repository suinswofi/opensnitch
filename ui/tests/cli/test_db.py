#
# pytest -v cli/test_db.py
#

from opensnitch.cli import db as dbmod


class TestQueue:

    def test_records_a_connection(self, db, connection):
        entry_id, is_new = db.record_pending("n", "sig", connection, {})

        assert is_new
        assert db.pending_count() == 1
        assert db.get_pending(entry_id)["process_path"] == "/usr/bin/curl"

    def test_counts_repeats(self, db, connection):
        first, _ = db.record_pending("n", "sig", connection, {})
        second, is_new = db.record_pending("n", "sig", connection, {})

        assert first == second
        assert not is_new
        assert db.get_pending(first)["hits"] == 2

    def test_each_node_has_its_own_queue(self, db, connection):
        db.record_pending("a", "sig", connection, {})
        db.record_pending("b", "sig", connection, {})
        assert db.pending_count() == 2

    def test_deciding_removes_it_from_the_queue(self, db, connection):
        entry_id, _ = db.record_pending("n", "sig", connection, {})
        db.set_pending_state(entry_id, dbmod.STATE_DECIDED, '{"name":"r"}')

        assert db.pending_count() == 0
        assert db.get_pending(entry_id)["decided_rule"] == '{"name":"r"}'

    def test_expired_provisional_rules_are_forgotten(self, db, connection):
        entry_id, _ = db.record_pending("n", "sig", connection,
                                        {"name": "cli-auto-x", "expires_in": -1})
        assert db.expire_provisionals() == 1
        assert db.get_pending(entry_id)["provisional_name"] is None

    def test_a_live_provisional_rule_is_kept(self, db, connection):
        entry_id, _ = db.record_pending("n", "sig", connection,
                                        {"name": "cli-auto-x", "expires_in": 3600})
        assert db.expire_provisionals() == 0
        assert db.get_pending(entry_id)["provisional_name"] == "cli-auto-x"


class TestOutbox:

    def test_lifecycle(self, db):
        outbox_id = db.queue_notification("n", 10, '{"name":"r"}')
        assert len(db.queued_notifications()) == 1

        db.mark_sent(outbox_id, 555)
        assert len(db.queued_notifications()) == 0
        assert db.get_outbox(outbox_id)["state"] == dbmod.OUT_SENT

        db.mark_result(555, True)
        assert db.get_outbox(outbox_id)["state"] == dbmod.OUT_DONE

    def test_a_rejected_rule_is_kept_with_its_reason(self, db):
        outbox_id = db.queue_notification("n", 10, "{}")
        db.mark_sent(outbox_id, 556)
        db.mark_result(556, False, "invalid regexp")

        errors = db.outbox_errors()
        assert len(errors) == 1
        assert errors[0]["last_error"] == "invalid regexp"

    def test_unanswered_notifications_are_sent_again_on_restart(self, db):
        """anything still marked as sent was in flight when the service stopped."""
        outbox_id = db.queue_notification("n", 10, "{}")
        db.mark_sent(outbox_id, 557)

        assert db.requeue_sent() == 1
        assert db.get_outbox(outbox_id)["state"] == dbmod.OUT_QUEUED

    def test_requeueing_one_node_leaves_the_others_alone(self, db):
        """when a node's stream drops, only its own notifications go back."""
        mine = db.queue_notification("a", 10, "{}")
        other = db.queue_notification("b", 10, "{}")
        db.mark_sent(mine, 1)
        db.mark_sent(other, 2)

        assert db.requeue_sent("a") == 1
        assert db.get_outbox(mine)["state"] == dbmod.OUT_QUEUED
        assert db.get_outbox(other)["state"] == dbmod.OUT_SENT

    def test_a_decision_survives_the_service_being_down(self, db):
        """review writes, serve reads later: nothing is lost in between."""
        db.queue_notification("n", 10, '{"name":"r"}')
        assert len(db.queued_notifications()) == 1

    def test_the_queue_can_be_read_per_node(self, db):
        for i in range(60):
            db.queue_notification("dead", 10, "{}")
        db.queue_notification("live", 10, '{"name":"r"}')

        assert len(db.queued_notifications(node="live")) == 1
        assert db.queued_count() == 61

    def test_a_rejected_rule_can_be_sent_again(self, db):
        outbox_id = db.queue_notification("n", 10, "{}")
        db.mark_sent(outbox_id, 558)
        db.mark_result(558, False, "invalid regexp")

        assert db.retry_errors() == 1
        row = db.get_outbox(outbox_id)
        assert row["state"] == dbmod.OUT_QUEUED
        assert row["last_error"] is None

    def test_clearing_a_rejected_rule_reopens_its_queue_entry(self, db, connection):
        """the decision never took, so it has to be taken again."""
        entry_id, _ = db.record_pending("n", "sig", connection, {})
        db.set_pending_state(entry_id, dbmod.STATE_DECIDED, '{"name":"bad"}')
        outbox_id = db.queue_notification("n", 10, '{"name":"bad"}', pending_id=entry_id)
        db.mark_sent(outbox_id, 559)
        db.mark_result(559, False, "invalid regexp")

        assert db.clear_errors() == 1
        assert db.outbox_errors() == []
        assert db.get_pending(entry_id)["state"] == dbmod.STATE_PENDING
        assert db.get_pending(entry_id)["decided_rule"] is None

    def test_names_handed_out_earlier_are_taken(self, db):
        """the rules table only knows what the daemon reported on connecting;
        what we sent since must not be handed out again."""
        db.queue_notification("n", 10, '{"name":"allow-always-list-usr-bin-curl"}')
        assert "allow-always-list-usr-bin-curl" in db.rule_names("n")
        assert "allow-always-list-usr-bin-curl" not in db.rule_names("other")



class TestConcurrentAccess:

    def test_two_connections_share_the_file(self, config, connection):
        """review and serve are separate processes on the same database."""
        writer = dbmod.Database(config.db_path())
        reader = dbmod.Database(config.db_path())

        writer.record_pending("n", "sig", connection, {})
        assert reader.pending_count() == 1

        reader.record_pending("n", "sig2", connection, {})
        assert writer.pending_count() == 2

        writer.close()
        reader.close()


class TestPurge:

    def test_keeps_entries_still_waiting(self, db, connection):
        db.record_pending("n", "sig", connection, {})
        assert db.purge(retention_days=30) == 0
        assert db.pending_count() == 1

    def test_disabled_by_zero(self, db, connection):
        entry_id, _ = db.record_pending("n", "sig", connection, {})
        db.set_pending_state(entry_id, dbmod.STATE_DECIDED)
        assert db.purge(retention_days=0) == 0
