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

"""Command line of opensnitch-cli.

grpc is only imported by the commands that need it, so that reviewing the queue
works on a machine where the service half isn't installed.
"""

import argparse
import json
import logging
import sys
import time

from opensnitch.version import version
from opensnitch.rule_consts import RuleConsts
from opensnitch.cli.config import Config, ConfigError

LOG_FORMAT = '%(asctime)s - [%(levelname)s][%(filename)s:%(lineno)d] %(message)s'


def setup_logging(config, level=None):
    level = level or config.get("log", "level")
    handlers = []
    log_file = config.get("log", "file")
    if log_file != "":
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(level=getattr(logging, level.upper()), format=LOG_FORMAT,
                        handlers=handlers, force=True)


def open_db(config):
    from opensnitch.cli import db as dbmod

    return dbmod.Database(config.db_path())


def cmd_serve(args, config):
    from opensnitch.cli.server import Server

    if args.socket is not None:
        config.set("server", "address", args.socket)

    server = Server(config)
    try:
        server.serve_forever()
    except RuntimeError as e:
        print("opensnitch-cli: %s" % e, file=sys.stderr)
        return 1
    return 0


def _entry_summary(entry):
    destination = entry["dst_host"] or entry["dst_ip"] or "?"
    return "%-5s %-28s %-38s %s" % (
        entry["id"],
        (entry["process_path"] or "?")[-28:],
        "%s:%s" % (destination, entry["dst_port"]),
        "%sx" % entry["hits"])


def cmd_pending(args, config):
    db = open_db(config)
    entries = db.pending(node=args.node, limit=args.limit)

    if args.json:
        print(json.dumps([dict(e) for e in entries], indent=2))
        return 0

    if len(entries) == 0:
        print("nothing waiting to be reviewed")
        return 0

    print("%-5s %-28s %-38s %s" % ("ID", "PROCESS", "DESTINATION", "SEEN"))
    for entry in entries:
        print(_entry_summary(entry))
    return 0


def cmd_review(args, config):
    from opensnitch.cli import review

    db = open_db(config)
    entries = db.pending(node=args.node, limit=args.limit)
    if len(entries) == 0:
        print("nothing waiting to be reviewed")
        return 0

    try:
        applied = review.review_loop(db, entries, config)
    except (KeyboardInterrupt, EOFError):
        print("")
        applied = 0

    if applied:
        if len(_served_nodes(db)) > 0:
            print("\n%d rule(s) queued. The service applies them within a second; "
                  "run 'opensnitch-cli status' to check." % applied)
        else:
            print("\n%d rule(s) queued, but no daemon is connected right now — is "
                  "'opensnitch-cli serve' running? The decisions are kept, and are "
                  "applied as soon as the service and the daemon are back." % applied)
    return 0


def _served_nodes(db, max_age=90):
    """the nodes the serve service is talking to right now.

    The online flag alone can lie: a serve process that dies never marks its
    nodes offline. While a node is connected its last_seen is refreshed every
    30 seconds (server.py LAST_SEEN_INTERVAL), so anything older than a couple
    of those is not actually being served.
    """
    now = time.time()
    return [n for n in db.nodes()
            if n["online"] and n["last_seen"] and now - n["last_seen"] < max_age]


def cmd_decide(args, config):
    """allow / deny / reject without the interactive loop."""
    from opensnitch.cli import review

    db = open_db(config)
    entry = db.get_pending(args.id)
    if entry is None:
        print("opensnitch-cli: no queue entry with id %s" % args.id, file=sys.stderr)
        return 1

    con = review.entry_connection(entry)
    decision = review.Decision(entry, con, args.action, args.duration,
                               db.rule_names(entry["node"]))

    if args.match is not None:
        matched = [c for c in decision.candidates if c["operand"] == args.match]
        if len(matched) == 0:
            print("opensnitch-cli: '%s' is not something this connection can be matched "
                  "on. Available: %s" % (
                      args.match, ", ".join(sorted(set(c["operand"] for c in decision.candidates)))),
                  file=sys.stderr)
            return 1
        decision.selected = matched[0]
    if args.name is not None:
        decision.name = args.name

    error = decision.validate()
    if error is not None:
        print("opensnitch-cli: %s" % error, file=sys.stderr)
        return 1

    rule = decision.build()
    review.apply_decision(db, entry, rule)
    print("queued: %s %s as '%s'" % (rule.action, rule.duration, rule.name))
    return 0


def cmd_drop(args, config):
    db = open_db(config)
    entry = db.get_pending(args.id)
    if entry is None:
        print("opensnitch-cli: no queue entry with id %s" % args.id, file=sys.stderr)
        return 1
    db.set_pending_state(args.id, "dropped")
    print("dropped entry %s, no rule created" % args.id)
    return 0


def cmd_rules(args, config):
    db = open_db(config)
    entries = db.rules(node=args.node)
    if args.json:
        print(json.dumps([dict(e) for e in entries], indent=2))
        return 0
    if len(entries) == 0:
        print("no rules known. They are read from each node when it connects.")
        return 0
    print("%-8s %-40s %-8s %s" % ("ENABLED", "NAME", "ACTION", "DURATION"))
    for rule in entries:
        print("%-8s %-40s %-8s %s" % (
            "yes" if rule["enabled"] else "no", rule["name"][:40], rule["action"],
            rule["duration"]))
    return 0


def cmd_nodes(args, config):
    db = open_db(config)
    nodes = db.nodes()
    if args.json:
        print(json.dumps([dict(n) for n in nodes], indent=2))
        return 0
    if len(nodes) == 0:
        print("no node has connected yet")
        return 0
    print("%-28s %-20s %-8s %s" % ("ADDRESS", "HOSTNAME", "ONLINE", "LAST SEEN"))
    for node in nodes:
        print("%-28s %-20s %-8s %s" % (node["addr"], node["hostname"] or "?",
                                       "yes" if node["online"] else "no", node["last_seen"]))
    return 0


def cmd_status(args, config):
    db = open_db(config)

    if args.retry:
        print("re-sending %d rejected notification(s)" % db.retry_errors())
    elif args.clear:
        print("dropped %d rejected notification(s); their connections are back in "
              "the review queue" % db.clear_errors())

    nodes = db.nodes()
    online = len([n for n in nodes if n["online"]])
    errors = db.outbox_errors()
    queued = db.queued_count()

    status = {
        "pending": db.pending_count(),
        "nodes": len(nodes),
        "nodes_online": online,
        "notifications_queued": queued,
        "notifications_failed": len(errors),
        "unreviewed_action": config.get("policy", "unreviewed_action"),
        "unreviewed_duration": config.get("policy", "unreviewed_duration"),
        "database": config.db_path(),
    }

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        for key, value in status.items():
            print("%-22s %s" % (key.replace("_", " "), value))
        for row in errors:
            print("\nrejected by the daemon: %s" % row["last_error"])
            print("  %s" % row["rule_json"].replace("\n", " "))

    # so that a monitoring system notices rules that never made it
    return 1 if len(errors) > 0 else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="opensnitch-cli",
        description="Review and answer OpenSnitch connection prompts from a terminal.")
    parser.add_argument("--version", action="version", version="opensnitch-cli %s" % version)
    parser.add_argument("--config", help="path to cli.conf")
    parser.add_argument("--db", help="path to the queue database, overrides the config file")
    parser.add_argument("--log-level", choices=("debug", "info", "warning", "error"))

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="answer the daemon and record connections")
    serve.add_argument("--socket", help="address to listen on, overrides the config file")
    serve.set_defaults(func=cmd_serve)

    pending = subparsers.add_parser("pending", help="list connections waiting to be reviewed")
    pending.add_argument("--node")
    pending.add_argument("--limit", type=int)
    pending.add_argument("--json", action="store_true")
    pending.set_defaults(func=cmd_pending)

    review_cmd = subparsers.add_parser("review", help="go through the queue one by one")
    review_cmd.add_argument("--node")
    review_cmd.add_argument("--limit", type=int)
    review_cmd.set_defaults(func=cmd_review)

    for action in (RuleConsts.ACTION_ALLOW, RuleConsts.ACTION_DENY, RuleConsts.ACTION_REJECT):
        decide = subparsers.add_parser(action, help="%s a queue entry without prompting" % action)
        decide.add_argument("id", type=int)
        decide.add_argument("--match", help="operand to match on, for example dest.host")
        decide.add_argument("--duration", default=RuleConsts.DURATION_ALWAYS)
        decide.add_argument("--name")
        decide.set_defaults(func=cmd_decide, action=action)

    drop = subparsers.add_parser("drop", help="remove a queue entry without creating a rule")
    drop.add_argument("id", type=int)
    drop.set_defaults(func=cmd_drop)

    rules_cmd = subparsers.add_parser("rules", help="rules the daemon reported on connecting")
    rules_cmd.add_argument("--node")
    rules_cmd.add_argument("--json", action="store_true")
    rules_cmd.set_defaults(func=cmd_rules)

    nodes = subparsers.add_parser("nodes", help="daemons that have connected")
    nodes.add_argument("--json", action="store_true")
    nodes.set_defaults(func=cmd_nodes)

    status = subparsers.add_parser("status", help="queue depth, nodes and failed rules")
    status.add_argument("--json", action="store_true")
    failed = status.add_mutually_exclusive_group()
    failed.add_argument("--retry", action="store_true",
                        help="send the rules the daemon rejected once more")
    failed.add_argument("--clear", action="store_true",
                        help="forget the rules the daemon rejected and put their "
                             "connections back in the review queue")
    status.set_defaults(func=cmd_status)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "func", None) is None:
        parser.print_help()
        return 2

    try:
        config = Config(path=args.config)
    except ConfigError as e:
        print("opensnitch-cli: %s" % e, file=sys.stderr)
        return 2

    if args.db is not None:
        config.set("db", "path", args.db)

    setup_logging(config, args.log_level)

    try:
        return args.func(args, config)
    except PermissionError as e:
        print("opensnitch-cli: %s\nThe queue is only readable by root, try with sudo." % e,
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
