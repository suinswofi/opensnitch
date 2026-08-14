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

    def test_a_decision_survives_the_service_being_down(self, db):
        """review writes, serve reads later: nothing is lost in between."""
        db.queue_notification("n", 10, '{"name":"r"}')
        assert len(db.queued_notifications()) == 1


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
