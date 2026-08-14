#   Copyright (C) 2026 The OpenSnitch Authors
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

"""What to answer when nobody has reviewed a connection yet.

The daemon holds the packet in a netfilter queue while it waits for our answer,
and gives up after two minutes (daemon/ui/client.go Ask). So we can't wait for
a person: we answer straight away with a temporary rule and put the connection
in the review queue, and the decision taken later governs everything after that.

The temporary rule is what stops the daemon asking again for every packet. It
is deliberately short lived, so that a connection nobody ever reviews comes back
to the queue instead of being allowed for good.
"""

import hashlib
import logging

from opensnitch.rule_consts import RuleConsts
from opensnitch.cli import durations, rules

PROVISIONAL_PREFIX = "cli-auto-"

logger = logging.getLogger(__name__)


def signature(node, con):
    """what makes two connections "the same thing" for review purposes.

    The process and where it is going, not how it got there: the pid, the source
    port and the source address change on every connection, and a host that
    resolves to a different address each time (any CDN) would otherwise fill the
    queue with duplicates.
    """
    parts = (
        node,
        con.process_path,
        " ".join(con.process_args),
        con.dst_host if con.dst_host != "" else con.dst_ip,
        str(con.dst_port),
        con.protocol,
        str(con.user_id),
    )
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def provisional_name(sig):
    return "%s%s" % (PROVISIONAL_PREFIX, sig[:12])


def provisional_operators(con):
    """the narrowest match that still covers the connection we were asked about.

    Matching only on the executable would let it reach anywhere for as long as
    the rule lives, so the destination is part of it too. Any other destination
    the same program tries gets its own queue entry, which is what makes the
    queue a useful list of "what does this machine talk to".
    """
    ops = []

    if con.process_path != "":
        ops.append(rules.new_operator(*operand_process_path(con)))

    if con.dst_host != "" and con.dst_host != con.dst_ip:
        ops.append(rules.new_operator(RuleConsts.RULE_TYPE_SIMPLE,
                                      RuleConsts.OPERAND_DEST_HOST, con.dst_host))
    elif con.dst_ip != "":
        ops.append(rules.new_operator(RuleConsts.RULE_TYPE_SIMPLE,
                                      RuleConsts.OPERAND_DEST_IP, con.dst_ip))

    if con.dst_port:
        ops.append(rules.new_operator(RuleConsts.RULE_TYPE_SIMPLE,
                                      RuleConsts.OPERAND_DEST_PORT, str(con.dst_port)))

    return ops


def operand_process_path(con):
    return (RuleConsts.RULE_TYPE_SIMPLE, RuleConsts.OPERAND_PROCESS_PATH, con.process_path)


def build_provisional(con, sig, action, duration):
    """the rule we hand back to the daemon for a connection nobody has reviewed."""
    ops = provisional_operators(con)
    if len(ops) == 0:
        # Nothing identifies this connection: no executable, no destination.
        # Rather than send a rule that matches everything, let the daemon apply
        # its own default action by sending nothing back.
        return None

    name = provisional_name(sig)
    description = "queued for review by opensnitch-cli"
    return rules.build_rule(name, action, duration, ops, description=description)


class Policy:
    """answers AskRule and keeps the review queue up to date."""

    def __init__(self, db, config):
        self._db = db
        self._action = config.get("policy", "unreviewed_action")
        self._duration = config.get("policy", "unreviewed_duration")
        self._queue_max = config.getint("policy", "queue_max")
        self._dropped = 0

    @property
    def action(self):
        return self._action

    @property
    def duration(self):
        return self._duration

    @property
    def dropped(self):
        return self._dropped

    def on_ask(self, node, con):
        """returns the rule to answer the daemon with, or None for its default.

        Never raises: an exception here becomes a gRPC error, the daemon logs a
        warning and applies its default action to a packet it is holding.
        """
        try:
            sig = signature(node, con)
            rule = build_provisional(con, sig, self._action, self._duration)
            if rule is None:
                logger.warning("connection with no process and no destination, "
                               "letting the daemon decide: %s", con)
                return None

            expires_in = durations.to_seconds(self._duration)
            provisional = {
                "name": rule.name,
                "action": rule.action,
                "duration": rule.duration,
                "expires_in": expires_in,
            }

            # A full queue must never stop us answering: the packet is waiting.
            # Existing entries still count new attempts, only new signatures are
            # refused, and the count is reported by 'opensnitch-cli status'.
            if self._db.pending_count() >= self._queue_max:
                existing = self._db.get_pending_by_signature(node, sig)
                if existing is None:
                    self._dropped += 1
                    if self._dropped == 1 or self._dropped % 100 == 0:
                        logger.warning("review queue is full (%d entries), not recording "
                                       "new connections (%d so far). Review the queue or "
                                       "raise policy.queue_max", self._queue_max, self._dropped)
                    return rule

            self._db.record_pending(node, sig, con, provisional)
            return rule
        except Exception as e:
            logger.error("error handling AskRule, letting the daemon decide: %s", repr(e))
            return None
