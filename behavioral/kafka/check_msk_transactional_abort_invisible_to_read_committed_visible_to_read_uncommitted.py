"""msk-transactional-abort-invisible-to-read-committed-visible-to-read-uncommitted."""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
import random
import secrets
import time
import zipfile

import kafka  # noqa: F401 - vendored INTO the executor package; see _make_zip
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "msk-transactional-abort-invisible-to-read-committed-visible-to-read-uncommitted"
GROUP = 'native-dataplane-transactions'
SERVICES = ['kafka']

# MSK Serverless speaks SASL/IAM over TLS on 9098 and offers no other listener at all -- no SCRAM,
# no mTLS, no PLAINTEXT -- which is why this is the only port the executor's security group needs.
_IAM_PORT = 9098

# The executor's own Lambda timeout. Three things derive from it and a disagreement between any two
# reports as "the instrument is unusable" instead of as a verdict about Kafka:
#   * the CreateFunction Timeout,
#   * the botocore READ timeout for Invoke, which must be LONGER (see _lambda_client),
#   * the retry budget the handler clamps itself to, which must be SHORTER (see handler()).
_FN_TIMEOUT_S = 300

# The reusable in-VPC executor network. VPC + subnets + security group are all FREE, and a Lambda
# with VpcConfig leaves a Hyperplane ENI holding the subnet for up to ~20 minutes after the function
# is deleted. So the network is looked up by this tag and REUSED rather than rebuilt and torn down:
# the ENI drain then blocks nothing, and Lambda reuses the ENI for the same
# (subnets, security-groups) tuple, which also removes ~60-90s of first-ENI latency per run.
_INFRA_TAG_KEY = "sim2real:infra"
_INFRA_TAG_VALUE = "kafka-dataplane-executor"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": "kafka-dataplane"},
    {"Key": _INFRA_TAG_KEY, "Value": _INFRA_TAG_VALUE},
]

# Grants ec2:CreateNetworkInterface / DescribeNetworkInterfaces / DeleteNetworkInterface plus the
# CloudWatch Logs actions. Without the EC2 half, CreateFunction with VpcConfig is REJECTED
# synchronously, which is why a Lambda execution role that carries
# only AWSLambdaBasicExecutionRole cannot be used here as-is.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# A native data-plane FAIL marker, load-bearing because the failure messages interpolate the
# errno text the in-VPC probe returned, and `Connection refused` / `timed out` read exactly like a
# transient fault of OUR OWN infrastructure -- so without a distinct marker the one verdict this
# check exists to produce (the target does not implement the data plane) is indistinguishable
# from our own environment being unhealthy.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


# ===== the in-VPC executor =====================================================================
#
# Real MSK brokers resolve ONLY to addresses inside the cluster's own VPC, and the test runner
# usually sits outside that VPC, so it has no route to them no matter how long it
# waits. The measurement therefore has to be CARRIED into the VPC, and a Lambda with VpcConfig is
# the cheapest vehicle for it.
#
# The deployment package vendors kafka-python out of this host's site-packages. kafka-python is pure
# Python with no compiled extension (0.59 MB zipped), and vendoring it is what makes the probe a
# REAL client: it speaks AWS_MSK_IAM over SASL_SSL through the same library a customer uses -- a
# first-class `kafka.net.sasl.SASL_MECHANISMS` entry in 3.0.10 that signs with botocore, needing no
# `aws-msk-iam-sasl-signer` helper (which is NOT installed here) -- so the handshake, the record
# format, the transaction protocol and the consumer-group protocol are all the real ones rather than
# a hand-framed subset that could only ever reach a PLAINTEXT listener.
#
# The handler is deliberately DUMB: it drives clients and returns values, and makes NO assertions.
# Every assertion lives in this file, because an assertion that fires inside the Lambda reports as
# `FunctionError: Unhandled` and leaves the interesting bytes only in the function's log group,
# which nothing here reads back. It also NEVER raises out of `handler`. Every failure is a value.

_HANDLER_SRC = r'''"""In-VPC MSK probe: vendored kafka-python, driven from inside the cluster's VPC."""
import base64, hashlib, json, os, random, socket, ssl, struct, sys, time, traceback


def _route_source_ip(host, port):
    """The source address the kernel WOULD use to reach host:port.

    connect() on a UDP socket sends no packet -- it only performs a route lookup and binds the
    local end -- so this is free and cannot be satisfied by anything listening at the far end.
    Pass an IP literal: on a hostname the call blocks in getaddrinfo instead.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, int(port)))
        return s.getsockname()[0]
    finally:
        s.close()


def _dns_query(resolver, name, timeout=3.0):
    """One hand-framed DNS A query straight at `resolver`. Returns (rcode, ancount).

    Hand-framed rather than socket.gethostbyname because THE RESOLVER IS THE SUBJECT: this must
    go to the address the caller nominated (the VPC CIDR base + 2, where the Route 53 Resolver
    lives) and not to whatever /etc/resolv.conf says. That address answers ONLY from inside that
    VPC and needs no NAT and no internet route, which makes a reply from it the cheapest
    available proof of VPC attachment.

    The datagram is validated on three counts -- source address, the QR bit, and our transaction
    id -- because the socket is unconnected and the kernel would otherwise hand back a datagram
    from ANY source as proof of VPC attachment.
    """
    qid = random.randrange(1, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p for p in (l.encode() for l in name.split("."))) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.monotonic() + timeout
    try:
        s.sendto(packet, (resolver, 53))
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ValueError("no DNS reply from %s matching id %d" % (resolver, qid))
            s.settimeout(left)
            data, addr = s.recvfrom(4096)
            if addr[0] != resolver or len(data) < 12:
                continue
            rid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
            if rid != qid or not flags & 0x8000:
                continue
            return flags & 0x000F, ancount
    finally:
        s.close()


def _selftest(event):
    """Prove (a) this code ran and (b) it ran inside the caller's VPC, before anything bills."""
    nonce = str(event.get("nonce", ""))
    resolver = event.get("resolver")
    src_ip = src_err = None
    try:
        src_ip = _route_source_ip(resolver, 53)
    except OSError as exc:
        src_err = "%s: errno=%s %s" % (type(exc).__name__, getattr(exc, "errno", None), exc)
    rcode = ancount = dns_err = None
    try:
        rcode, ancount = _dns_query(resolver, event.get("dns_name") or "amazonaws.com")
    except Exception as exc:
        dns_err = "%s: %s" % (type(exc).__name__, exc)
    try:
        import kafka
        kver = kafka.__version__
    except Exception as exc:
        kver = "IMPORT FAILED: %s: %s" % (type(exc).__name__, exc)
    try:
        import botocore
        bver = botocore.__version__
    except Exception as exc:
        bver = "IMPORT FAILED: %s: %s" % (type(exc).__name__, exc)
    return {"ok": True, "nonce": nonce,
            # The same f-string on both sides, over the network fields too, so a target that runs
            # the code and then rewrites the response invalidates its own proof.
            "proof": hashlib.sha256(("%s|%s|%s" % (nonce, src_ip, rcode)).encode()).hexdigest(),
            "src_ip": src_ip, "src_ip_error": src_err, "resolver": resolver,
            "resolver_rcode": rcode, "resolver_ancount": ancount, "resolver_error": dns_err,
            "kafka_python": kver, "botocore": bver,
            "region_env": os.environ.get("AWS_REGION"), "python": sys.version.split()[0]}


def _tls_context():
    """TLS without verifying the broker's identity (SimParity CONTRACT.md, Artifact TLS)."""
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _tcp_ready(event):
    """ONE short TCP connect to the bootstrap endpoint. The readiness barrier's probe.

    Deliberately a single attempt with no internal retry: the caller polls this from OUTSIDE the
    Lambda, so the wait is bounded by the CHECK's deadline rather than by a sandbox timeout, and
    every attempt is visible in the run's output instead of being buried in a log group.
    """
    host, _, port = event["bootstrap"].split(",")[0].rpartition(":")
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, int(port)), timeout=float(event.get("timeout_s", 10)))
    except Exception as exc:
        return {"ok": True, "connected": False, "seconds": round(time.monotonic() - t0, 2),
                "target": "%s:%s" % (host, port),
                "error": "%s: errno=%s %s" % (type(exc).__name__,
                                              getattr(exc, "errno", None), exc)}
    out = {"ok": True, "connected": True, "seconds": round(time.monotonic() - t0, 2),
           "target": "%s:%s" % (host, port), "peer": s.getpeername()[0]}
    # A TLS handshake, without verifying the broker's identity.
    try:
        ts = _tls_context().wrap_socket(s, server_hostname=host)
        out["tls_version"] = ts.version()
        ts.close()
    except Exception as exc:
        out["tls_error"] = "%s: %s" % (type(exc).__name__, exc)
        try:
            s.close()
        except Exception:
            pass
    return out


def _conn(event):
    """kafka-python connection kwargs. NOTE: api_version_auto_timeout_ms is NOT a valid config
    for KafkaAdminClient in kafka-python 3.0.10 -- it raises KafkaConfigurationError
    ('Unrecognized configs'), measured against a live cluster -- so it is never passed."""
    return {"bootstrap_servers": event["bootstrap"].split(","),
            "security_protocol": event.get("security_protocol", "SASL_SSL"),
            "ssl_context": _tls_context(),
            "sasl_mechanism": event.get("sasl_mechanism", "AWS_MSK_IAM"),
            "request_timeout_ms": int(event.get("request_timeout_ms", 60000))}


def _connect_errors():
    """Only the errors that a not-yet-accepting broker actually raises.

    Deliberately NOT `Exception`. A KafkaConfigurationError is deterministic and retrying it
    burns the whole budget to reach the same answer. Resolved by NAME rather than imported,
    because the names moved: `NoBrokersAvailable` DOES NOT EXIST in kafka-python 3.0.10, and a
    hard import of it raises ImportError inside the handler and takes the whole op down.
    """
    import kafka.errors as ke
    wanted = ("KafkaConnectionError", "KafkaTimeoutError", "MetadataEmptyBrokerList",
              "NodeNotReadyError", "NoBrokersAvailable")
    found = tuple(getattr(ke, n) for n in wanted if hasattr(ke, n))
    assert len(found) >= 2, "kafka.errors exposes none of %r" % (wanted,)
    return found + (OSError,)


def _retry(fn, budget_s):
    """Call fn() until it stops raising a CONNECTION error or budget_s runs out.

    A cluster MSK reports ACTIVE, with GetBootstrapBrokers already answering, does not
    necessarily accept TCP yet, so one attempt decides the verdict by luck.
    """
    end = time.monotonic() + budget_s
    attempts = []
    while True:
        try:
            return fn(), attempts
        except _connect_errors() as exc:
            attempts.append("%s: %s" % (type(exc).__name__, exc))
            if time.monotonic() >= end:
                raise
            time.sleep(5)


def _err(exc):
    """Every name a refusal has, including the PROTOCOL name of a WRAPPED cause.

    The wrapped cause is the load-bearing part. kafka-python 3.0.10 converts an OffsetCommit
    refused with ILLEGAL_GENERATION or UNKNOWN_MEMBER_ID into `CommitFailedError(cause())`
    (kafka/coordinator/consumer.py:1034), and `CommitFailedError` itself carries neither `errno`
    nor `message` -- so a check that reads only the outer class name cannot name the Kafka
    protocol error at all, and would have to assert on a Python class name instead of on the wire.
    `args[0]` is the original error INSTANCE, whose class carries `.errno` and `.message`.
    """
    out = {"type": type(exc).__name__, "error": str(exc)[:400],
           "kafka_error": getattr(exc, "message", None),
           "kafka_errno": getattr(exc, "errno", None),
           "cause_type": None, "cause_kafka_error": None, "cause_kafka_errno": None}
    for arg in getattr(exc, "args", ()) or ():
        if isinstance(arg, BaseException):
            out["cause_type"] = type(arg).__name__
            out["cause_kafka_error"] = getattr(arg, "message", None)
            out["cause_kafka_errno"] = getattr(arg, "errno", None)
            break
    return out


def _kafka_ready(event):
    """ONE short attempt at a real Kafka ADMIN PROTOCOL call. The second half of the barrier.

    A completed TCP handshake is not enough and that is measured, not defensive: after
    `tcp_ready` succeeds, `KafkaAdminClient(...)` can still connect and then have `create_topics`
    time out with KafkaConnectionError.

    The operation is a METADATA fetch (`list_topics`), deliberately not `describe_cluster`:
    kafka-python 3.0.10's `describe_cluster()` raises `KeyError: 'endpoint_type'` against MSK
    Serverless, which made the wait unsatisfiable on a cluster that was in fact ready.
    """
    from kafka.admin import KafkaAdminClient
    t0 = time.monotonic()
    try:
        admin = KafkaAdminClient(**dict(_conn(event), request_timeout_ms=20000))
    except Exception as exc:
        return {"ok": True, "serving": False, "phase": "connect",
                "seconds": round(time.monotonic() - t0, 2),
                "error": "%s: %s" % (type(exc).__name__, exc)}
    try:
        topics = admin.list_topics()
        return {"ok": True, "serving": True, "seconds": round(time.monotonic() - t0, 2),
                "n_topics": len(topics)}
    except Exception as exc:
        return {"ok": True, "serving": False, "phase": "describe",
                "seconds": round(time.monotonic() - t0, 2),
                "error": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        try:
            admin.close()
        except Exception:
            pass


def _admin(event, budget_s):
    """Create the topic over the native admin protocol, then read the broker's own view back."""
    from kafka.admin import ConfigResource, ConfigResourceType, KafkaAdminClient, NewTopic
    from kafka.errors import TopicAlreadyExistsError
    out = {"ok": False, "stage": "connect"}
    admin, out["connect_attempts"] = _retry(lambda: KafkaAdminClient(**_conn(event)), budget_s)
    try:
        out["stage"] = "create_topic"
        topic = event["topic"]

        def _create():
            try:
                admin.create_topics([NewTopic(
                    name=topic, num_partitions=int(event.get("partitions", 1)),
                    replication_factor=int(event.get("replication", -1)),
                    topic_configs=event.get("topic_configs") or None)])
            except TopicAlreadyExistsError:
                out["already_existed"] = True

        # CreateTopics is retried on CONNECTION errors, not just the initial connect: with both
        # readiness barriers green a 3-partition CreateTopics still came back
        # KafkaConnectionError. Retrying is safe because a create that already landed raises
        # TopicAlreadyExistsError, which is absorbed above.
        _, out["create_attempts"] = _retry(_create, min(budget_s, 180))
        out["stage"] = "wait_for_topics"
        try:
            admin.wait_for_topics([topic], timeout_ms=int(event.get("topic_wait_ms", 60000)))
            out["topic_ready"] = True
        except Exception as exc:
            out["topic_ready"] = False
            out["wait_for_topics_error"] = "%s: %s" % (type(exc).__name__, exc)
        out["stage"] = "describe_topics"
        try:
            described = admin.describe_topics(topics=[topic])
            out["described"] = [
                {"name": t.get("name"), "error_code": t.get("error_code"),
                 "n_partitions": len(t.get("partitions") or []),
                 "leaders": sorted(p.get("leader_id") for p in (t.get("partitions") or []))}
                for t in (described or [])]
        except Exception as exc:
            out["describe_topics_error"] = "%s: %s" % (type(exc).__name__, exc)
        out["stage"] = "list_topics"
        out["topics"] = sorted(admin.list_topics())
        out["stage"] = "describe_configs"
        try:
            # kafka-python 3.0.10 returns a DICT here, not response objects:
            #   {resource_type: {resource_name: {config_name: {"value": ..., ...}}}}
            raw = admin.describe_configs(
                [ConfigResource(ConfigResourceType.TOPIC, topic)], config_filter="all")
            entries = (raw.get("topic") or {}).get(topic) or {}
            out["topic_configs"] = {
                name: (cfg.get("value") if isinstance(cfg, dict) else cfg)
                for name, cfg in entries.items()}
        except Exception as exc:
            out["describe_configs_error"] = "%s: %s" % (type(exc).__name__, exc)
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        out["traceback"] = traceback.format_exc()[-900:]
    finally:
        try:
            admin.close()
        except Exception:
            pass
    return out


def _rec(m):
    """One consumed record. Bytes are base64 so a NULL value and an EMPTY one stay
    distinguishable in transit: JSON cannot otherwise carry b"" apart from None."""
    hdrs = []
    for hk, hv in (m.headers or []):
        hdrs.append([hk, None if hv is None else base64.b64encode(hv).decode()])
    return {"partition": m.partition, "offset": m.offset, "timestamp": m.timestamp,
            "timestamp_type": m.timestamp_type,
            "key": None if m.key is None else base64.b64encode(m.key).decode(),
            "value": None if m.value is None else base64.b64encode(m.value).decode(),
            "headers": hdrs}


def _read(event, budget_s):
    """Read a partition from its beginning at a chosen isolation level. ASSIGN, never subscribe.

    Assignment rather than a consumer group is deliberate and it is what makes an EMPTY result
    trustworthy. A subscribing consumer's empty read has two explanations -- an empty log, or a
    group join that never completed -- and only one of them is about the broker. With an explicit
    assign() plus seek_to_beginning() the consumer's position is a fact this code set, so zero
    records means the broker served zero records at those coordinates.

    The poll loop always runs to its deadline when it has not reached `max_records`, so proving an
    ABSENCE costs the full `poll_budget_s` rather than returning early on the first empty batch.
    """
    from kafka import KafkaConsumer, TopicPartition
    out = {"ok": False, "stage": "connect"}
    kw = _conn(event)
    kw.update(enable_auto_commit=False,
              isolation_level=event.get("isolation_level", "read_uncommitted"),
              consumer_timeout_ms=int(event.get("consumer_timeout_ms", 4000)))
    cons, out["connect_attempts"] = _retry(lambda: KafkaConsumer(**kw), budget_s)
    try:
        topic = event["topic"]
        parts = [int(p) for p in (event.get("partitions") or [0])]
        tps = [TopicPartition(topic, p) for p in parts]
        out["isolation_level"] = kw["isolation_level"]
        out["stage"] = "assign"
        cons.assign(tps)
        cons.seek_to_beginning(*tps)
        out["positions"] = {"%d" % tp.partition: cons.position(tp) for tp in tps}
        # end_offsets/beginning_offsets go through ListOffsets, which on this client carries the
        # consumer's own isolation_level -- so for a read_committed consumer the "end" is the LAST
        # STABLE OFFSET and for a read_uncommitted one it is the HIGH WATERMARK. Both are reported
        # because the difference between them is the whole subject of the transactional check.
        out["stage"] = "offsets"
        out["end_offsets"] = {"%d" % tp.partition: o
                              for tp, o in cons.end_offsets(tps).items()}
        out["beginning_offsets"] = {"%d" % tp.partition: o
                                    for tp, o in cons.beginning_offsets(tps).items()}
        out["stage"] = "poll"
        recs = []
        want = int(event.get("max_records", 200))
        polls = 0
        deadline = time.monotonic() + float(event.get("poll_budget_s", 20))
        while len(recs) < want and time.monotonic() < deadline:
            polls += 1
            for _tp, msgs in cons.poll(timeout_ms=1500, max_records=want - len(recs)).items():
                for m in msgs:
                    if len(recs) < want:
                        recs.append(_rec(m))
        out["polls"] = polls
        out["records"] = recs
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        out["traceback"] = traceback.format_exc()[-900:]
    finally:
        try:
            cons.close()
        except Exception:
            pass
    return out


def _offsets(event, budget_s):
    """ListOffsets EARLIEST and LATEST at BOTH isolation levels, from the ADMIN protocol.

    This is the sharpest instrument in the transactional check and the reason the admin client is
    used rather than a consumer: `ListOffsets(LATEST)` answers with the HIGH WATERMARK under
    read_uncommitted and with the LAST STABLE OFFSET under read_committed. Identical request
    coordinates, one flag apart, two different numbers -- which no recorded response can
    reproduce, because nothing else in the request distinguishes them.
    """
    from kafka import IsolationLevel, OffsetSpec, TopicPartition
    from kafka.admin import KafkaAdminClient
    out = {"ok": False, "stage": "connect"}
    admin, out["connect_attempts"] = _retry(lambda: KafkaAdminClient(**_conn(event)), budget_s)
    try:
        topic = event["topic"]
        parts = [int(p) for p in (event.get("partitions") or [0])]
        out["stage"] = "list_partition_offsets"
        res = {}
        for lvl_name, lvl in (("read_uncommitted", IsolationLevel.READ_UNCOMMITTED),
                              ("read_committed", IsolationLevel.READ_COMMITTED)):
            res[lvl_name] = {}
            for spec_name, spec in (("latest", OffsetSpec.LATEST),
                                    ("earliest", OffsetSpec.EARLIEST)):
                got = admin.list_partition_offsets(
                    {TopicPartition(topic, p): spec for p in parts}, isolation_level=lvl)
                res[lvl_name][spec_name] = {"%d" % tp.partition: ot.offset
                                            for tp, ot in got.items()}
        out["offsets"] = res
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        out["traceback"] = traceback.format_exc()[-900:]
    finally:
        try:
            admin.close()
        except Exception:
            pass
    return out


def _txn_producer(event, budget_s, transactional_id):
    """A TRANSACTIONAL producer, already through InitProducerId.

    `enable_idempotence` is left at kafka-python 3.0.10's default (True) and is mandatory with a
    `transactional_id`; `acks='all'` because a transaction's records must be in the ISR before the
    marker that decides their fate. `transaction_timeout_ms` has to outlive the whole in-flight
    SNAPSHOT taken while the transaction is still open (two reads plus a ListOffsets pair), or the
    broker aborts the transaction on its own timer and the abort under test is not ours.
    """
    from kafka import KafkaProducer
    kw = _conn(event)
    kw.update(acks="all", enable_idempotence=True, transactional_id=transactional_id,
              transaction_timeout_ms=int(event.get("transaction_timeout_ms", 180000)))
    prod, attempts = _retry(lambda: KafkaProducer(**kw), budget_s)
    prod.init_transactions()
    return prod, attempts


def _send_batch(prod, topic, records, flush_s=60):
    """Send every record, flush, and return the coordinates the BROKER assigned to each.

    Metadata is collected BEFORE the caller commits or aborts, which is the point: it proves the
    records were physically APPENDED to the log while the transaction was still open, so a later
    absence under read_committed is a filtering decision rather than a write that never happened.
    """
    futures = [prod.send(topic,
                         key=None if r[0] is None else base64.b64decode(r[0]),
                         value=None if r[1] is None else base64.b64decode(r[1]),
                         partition=(r[2] if len(r) > 2 else None))
               for r in records]
    flush_err = None
    try:
        prod.flush(timeout=flush_s)
    except Exception as exc:
        flush_err = "%s: %s" % (type(exc).__name__, exc)
    meta, errors = [], []
    for i, f in enumerate(futures):
        try:
            m = f.get(timeout=30)
            meta.append({"i": i, "partition": m.partition, "offset": m.offset})
        except Exception as exc:
            errors.append(dict(_err(exc), i=i))
    return {"metadata": meta, "errors": errors, "flush_error": flush_err}


def _snapshot(event, tag):
    """What both isolation levels can see RIGHT NOW: ListOffsets at each level, plus a full read at
    each level. Four broker answers about one partition, taken at one instant."""
    ev = dict(event)
    return {
        "tag": tag,
        "offsets": _offsets(ev, 30),
        "read_committed": _read(dict(ev, isolation_level="read_committed",
                                     poll_budget_s=float(event.get("snap_poll_s", 15))), 30),
        "read_uncommitted": _read(dict(ev, isolation_level="read_uncommitted",
                                       poll_budget_s=float(event.get("snap_poll_s", 15))), 30),
    }


def _txn_cycle(event, budget_s):
    """Append a batch inside an OPEN transaction, snapshot the log, ABORT, then commit a second
    batch and snapshot again.

    The in-flight snapshot is the part no single AWS API call reaches. Between the flush and
    the abort the partition holds five records that are physically present and not yet decided, so
    a read_uncommitted client must see all five while a read_committed client must see NONE -- and
    ListOffsets(LATEST) must answer with two different numbers depending only on the isolation
    level flag.
    """
    out = {"ok": False, "stage": "connect"}
    tid = event["transactional_id"]
    prod, out["connect_attempts"] = _txn_producer(event, budget_s, tid)
    try:
        out["stage"] = "aborted_batch"
        prod.begin_transaction()
        out["aborted_batch"] = _send_batch(prod, event["topic"], event["aborted_records"])
        out["stage"] = "snapshot_inflight"
        out["inflight"] = _snapshot(event, "inflight")
        out["stage"] = "abort_transaction"
        prod.abort_transaction()
        out["aborted"] = True
        out["stage"] = "committed_batch"
        prod.begin_transaction()
        out["committed_batch"] = _send_batch(prod, event["topic"], event["committed_records"])
        out["stage"] = "commit_transaction"
        prod.commit_transaction()
        out["committed"] = True
        out["stage"] = "snapshot_final"
        out["final"] = _snapshot(event, "final")
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out.update(_err(exc))
        out["traceback"] = traceback.format_exc()[-1200:]
    finally:
        try:
            prod.close(timeout=15)
        except Exception:
            pass
    return out


def _txn_fence(event, budget_s):
    """Two producers, one transactional id. The second's InitProducerId must FENCE the first.

    Run on its own topic so the fenced record cannot perturb the offset arithmetic of the abort
    cycle above. Three arms in one invoke, because all three need producer objects alive at the
    same time:
      * the fenced producer's `commit_transaction()` -- expected to be refused;
      * the effect: whatever that producer appended must never become committed;
      * the control: a producer with a FRESH transactional id commits on the same topic, proving
        the broker's transaction coordinator is still serving and the refusal was about the epoch.
    """
    out = {"ok": False, "stage": "connect_p1"}
    tid = event["transactional_id"]
    topic = event["topic"]
    p1 = p2 = p3 = None
    try:
        p1, out["p1_connect_attempts"] = _txn_producer(event, budget_s, tid)
        out["stage"] = "p1_open_batch"
        p1.begin_transaction()
        out["p1_batch"] = _send_batch(p1, topic, event["fenced_records"])
        out["stage"] = "connect_p2_same_transactional_id"
        # InitProducerId for a transactional id that already has a producer bumps the epoch, which
        # is the fencing act itself: it also aborts p1's open transaction server-side.
        p2, out["p2_connect_attempts"] = _txn_producer(event, budget_s, tid)
        out["p2_initialized"] = True
        out["stage"] = "p1_commit_after_fence"
        try:
            p1.commit_transaction()
            out["p1_commit"] = {"refused": False}
        except Exception as exc:
            out["p1_commit"] = dict(_err(exc), refused=True)
        out["stage"] = "control_fresh_transactional_id"
        p3, out["p3_connect_attempts"] = _txn_producer(event, budget_s,
                                                       event["control_transactional_id"])
        p3.begin_transaction()
        out["control_batch"] = _send_batch(p3, topic, event["control_records"])
        p3.commit_transaction()
        out["control_committed"] = True
        out["stage"] = "snapshot_final"
        out["final"] = _snapshot(event, "fence_final")
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out.update(_err(exc))
        out["traceback"] = traceback.format_exc()[-1200:]
    finally:
        for p in (p3, p2, p1):
            try:
                if p is not None:
                    p.close(timeout=10)
            except Exception:
                pass
    return out


def handler(event, context):
    op = (event or {}).get("op")
    try:
        # Clamp the retry budget to the remaining sandbox time. A budget larger than that is
        # actively harmful: the invoke is killed, Sandbox.Timedout comes back as a FunctionError,
        # and the caller reads that as "the executor is unusable" rather than as a verdict.
        budget = max(10.0, (context.get_remaining_time_in_millis() / 1000.0) - 25.0)
    except Exception:
        budget = float(event.get("budget_s", 120))
    try:
        if op == "selftest":
            return _selftest(event)
        if op == "tcp_ready":
            return _tcp_ready(event)
        if op == "kafka_ready":
            return _kafka_ready(event)
        fn = {"admin": _admin, "read": _read, "offsets": _offsets,
              "txn_cycle": _txn_cycle, "txn_fence": _txn_fence}.get(op)
        if fn is None:
            return {"ok": False, "stage": "dispatch", "error": "unknown op %r" % (op,)}
        return fn(event, budget)
    except Exception as exc:
        return {"ok": False, "stage": "handler", "type": type(exc).__name__,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "traceback": traceback.format_exc()[-1500:]}
'''


# ===== local helpers (self-contained) ===========================================================


def _dp_fail(msg: str) -> AssertionError:
    """The native data-plane fidelity failure, distinct from an infrastructure fault. Returned
    rather than raised so a call site keeps its `from exc` chaining."""
    return AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _no_executor(msg: str):
    """The in-VPC executor is unusable, so this run measured nothing."""
    return AssertionError(f"the in-VPC executor is unusable, so this run measured nothing: {msg}")


def _code_of(exc: ClientError) -> str:
    """The error code with its modelled Exception/Fault suffix stripped.

    EVERY comparison against this must use the BASE form: `NotFoundException` arrives here as
    `NotFound`, so a check written against the wire name silently never matches.
    """
    code = exc.response.get("Error", {}).get("Code") or ""
    for suffix in ("Exception", "Fault"):
        if code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _msg_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _paginate(client, op: str, key: str, **kwargs):
    """Every page of `op`, flattened on `key`. An account can hold many resources, so a single
    un-paginated Describe can miss ours."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 — no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _poll(probe, predicate, *, timeout_s: float, interval_s: float):
    """Poll `probe` until `predicate`. Returns the last observation, or None on timeout. Returns
    rather than raises so the caller decides the verdict."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


# ---- the reusable executor network -----------------------------------------------------------

# Base forms only — see _code_of. Throttling and authorization failures say nothing about whether
# a target can tag-filter, and treating them as a miss is what turns one failing Describe into a
# new retained VPC on every run, bounded only by the region's VPC quota.
_DESCRIBE_MUST_NOT_SWALLOW = frozenset({
    "RequestLimitExceeded", "Throttling", "TooManyRequests",
    "UnauthorizedOperation", "AccessDenied", "AuthFailure",
    "OptInRequired", "RequestExpired", "InvalidClientTokenId", "UnrecognizedClient",
})
_SUBNET_RACE_LOST = frozenset({"InvalidSubnet.Conflict", "InvalidSubnetRange.Conflict"})


def _tag_filter():
    return [{"Name": f"tag:{_INFRA_TAG_KEY}", "Values": [_INFRA_TAG_VALUE]}]


def _has_rule(ec2, sg_id: str, port: int, *, egress: bool) -> bool:
    """Does sg_id already allow tcp/`port` TO/FROM ITSELF, in the given direction?

    Matched on the GROUP PAIR, not on a CIDR: a 0.0.0.0/0 rule on the data port would let the
    round trip succeed without proving the packets travelled between ENIs we attached, which is
    the whole load the self-reference carries.
    """
    key = "IpPermissionsEgress" if egress else "IpPermissions"
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups", GroupIds=[sg_id])
    for perm in (groups[0].get(key, []) if groups else []):
        if perm.get("IpProtocol") != "tcp":
            continue
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if lo is None or hi is None or not (lo <= port <= hi):
            continue
        if any(p.get("GroupId") == sg_id for p in perm.get("UserIdGroupPairs", [])):
            return True
    return False


def _ensure_rule(ec2, sg_id: str, port: int, *, egress: bool) -> None:
    """Authorize the self-referencing rule unless it is already there. Idempotent because BOTH
    network paths must guarantee it, not just the create path.

    The EGRESS half is the expensive one and it is not defensive padding. A brand-new group gets
    AWS's default allow-all egress; something later revokes it and from then on the RETAINED group
    can receive on the data port and send nothing. That failure is invisible to the in-VPC control
    step, because BOTH of its proofs bypass security groups — so `in_vpc` reads true while the data
    port is silently dead, and the check would emit DATAPLANE_UNIMPLEMENTED for a defect of our own
    infrastructure.
    """
    if _has_rule(ec2, sg_id, port, egress=egress):
        return
    call = ec2.authorize_security_group_egress if egress else ec2.authorize_security_group_ingress
    try:
        call(GroupId=sg_id, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "UserIdGroupPairs": [{"GroupId": sg_id,
                                  "Description": "sim2real in-VPC executor to MSK, same group"}]}])
    except ClientError as exc:
        # Two runs racing on the same reused group: the loser's rule is the rule we wanted.
        if _code_of(exc) != "InvalidPermission.Duplicate":
            raise
    assert _has_rule(ec2, sg_id, port, egress=egress), (
        f"{sg_id} still does not permit tcp/{port} "
        f"{'egress to' if egress else 'ingress from'} itself after authorizing; the round trip "
        f"below could not distinguish this from a broken data plane")


def _usable_azs(ec2, want: int = 2) -> list[str]:
    """`want` availability zones this account can actually place a subnet in. Never a hardcoded
    zone name — AZ names are per-account aliases for different physical zones. MSK publishes no
    per-AZ catalogue to intersect against, so the structural mitigation is spanning two zones,
    which costs nothing."""
    zones = _paginate(ec2, "describe_availability_zones", "AvailabilityZones", Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}])
    names = sorted(z["ZoneName"] for z in zones)
    assert len(names) >= want, (
        f"{ec2.meta.region_name!r} offers only {names!r} available non-opt-in zones, and MSK "
        f"needs {want} in distinct zones; this region cannot host the executor")
    return names[:want]


def _ensure_subnets(ec2, vpc_id: str, cidr: str, existing: list, want: int = 2) -> list[str]:
    """The executor subnets, completed to `want` DISTINCT availability zones.

    Counting ZONES rather than subnets is the point: a predecessor that died between the two
    creates leaves exactly one tagged subnet, and treating any non-empty set as complete would
    reuse that single-AZ network forever.
    """
    ids = [s["SubnetId"] for s in existing]
    azs = {s.get("AvailabilityZone") for s in existing} - {None}
    octets = {int(s["CidrBlock"].split(".")[2]) for s in existing if s.get("CidrBlock")}
    for az in _usable_azs(ec2, want):
        if len(azs) >= want:
            break
        if az in azs:
            continue
        octet = next(i for i in range(1, 255) if i not in octets)
        try:
            ids.append(ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.{cidr.split('.')[1]}.{octet}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
            )["Subnet"]["SubnetId"])
        except ClientError as exc:
            # Two checks racing in the same account derive the same deterministic CIDR, so
            # the loser adopts the winner's subnets rather than failing the run.
            if _code_of(exc) not in _SUBNET_RACE_LOST:
                raise
            adopted = sorted(s["SubnetId"] for s in _paginate(
                ec2, "describe_subnets", "Subnets",
                Filters=_tag_filter() + [{"Name": "vpc-id", "Values": [vpc_id]}]))
            return adopted or ids
        azs.add(az)
        octets.add(octet)
    assert len(ids) >= want, f"only created {ids!r} in {vpc_id}, need {want} subnets"
    return sorted(ids)


def _ensure_sg(ctx, ec2, vpc_id: str, existing: list) -> str:
    """The executor security group, created if absent, always carrying the self rules.

    The self-reference is a second control, not a style choice. Both the Lambda ENI (via
    VpcConfig) and the cluster's endpoints (via SecurityGroups) sit in this ONE group, and the
    only rule admits tcp/9098 from members of the group itself — never a CIDR, never 0.0.0.0/0.
    A successful connect through it therefore PROVES the packets originated from an ENI in the
    group we attached; a CIDR rule would prove only that the source address looked right.
    """
    sg_id = (sorted(g["GroupId"] for g in existing)[0] if existing
             else ec2.create_security_group(
                 GroupName=ctx.unique_name("sim2real-behav-kdp-sg-"),
                 Description="sim2real kafka in-VPC executor: Lambda ENI + MSK, self-referencing",
                 VpcId=vpc_id,
                 TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
             )["GroupId"])
    _ensure_rule(ec2, sg_id, _IAM_PORT, egress=False)
    _ensure_rule(ec2, sg_id, _IAM_PORT, egress=True)
    return sg_id


def _network(ctx, ec2) -> dict:
    """The tagged executor VPC, COMPLETED where it is partial, created only if none exists.

    Lowest VpcId wins if two exist: two checks racing in the same account can each create
    one, and a deterministic tie-break makes the duplicate inert instead of flapping. That same
    tie-break is why a partial network must be completed rather than rejected — a VPC whose
    predecessor died between create_vpc and create_subnet is still the lowest VpcId, so treating
    it as absent would mint another RETAINED VPC on every future run.

    Nothing here is registered for cleanup, deliberately: see the module comment on _INFRA_TAG_KEY.
    """
    try:
        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs",
                         Filters=_tag_filter() + [{"Name": "state", "Values": ["available"]}])
    except ClientError as exc:
        if _code_of(exc) in _DESCRIBE_MUST_NOT_SWALLOW:
            raise
        vpcs = []
    if vpcs:
        vpc = sorted(vpcs, key=lambda v: v["VpcId"])[0]
        vpc_id, cidr = vpc["VpcId"], vpc.get("CidrBlock")
        assert cidr, f"{vpc_id} has no CidrBlock, so the resolver address cannot be derived"
    else:
        # A randomized second octet makes the "is the executor's source address inside our VPC"
        # assertion sharp: a target with a flat network is vanishingly unlikely to hand out an
        # address in 10.<random>.0.0/16.
        cidr = f"10.{random.randrange(20, 250)}.0.0/16"
        vpc_id = ec2.create_vpc(
            CidrBlock=cidr,
            TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}])["Vpc"]["VpcId"]
        print(f"[ledger] created RETAINED executor VPC {vpc_id} cidr={cidr}")
    # EnableDnsSupport defaults on but EnableDnsHostnames does NOT, and the resolver at
    # CIDR-base+2 only answers when DNS support is on — which is one of the two in-VPC proofs.
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})
    subnets = _paginate(ec2, "describe_subnets", "Subnets",
                        Filters=_tag_filter() + [{"Name": "vpc-id", "Values": [vpc_id]}])
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups",
                       Filters=_tag_filter() + [{"Name": "vpc-id", "Values": [vpc_id]}])
    net = {"vpc_id": vpc_id, "cidr": cidr,
           "resolver": str(ipaddress.ip_network(cidr).network_address + 2),
           "subnet_ids": _ensure_subnets(ec2, vpc_id, cidr, subnets),
           "sg_id": _ensure_sg(ctx, ec2, vpc_id, groups)}
    print(f"[ledger] executor network vpc={net['vpc_id']} subnets={net['subnet_ids']} "
          f"sg={net['sg_id']} (RETAINED, tagged {_INFRA_TAG_VALUE})")
    return net


# ---- the executor: role + function -----------------------------------------------------------

_LAMBDA_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
     "Action": "sts:AssumeRole"}]}

#: The kafka-cluster actions MSK's IAM authorizer consults for this check's data plane.
_MSK_ACTIONS = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster",
                "kafka-cluster:DescribeClusterDynamicConfiguration",
                "kafka-cluster:CreateTopic", "kafka-cluster:DeleteTopic",
                "kafka-cluster:DescribeTopic", "kafka-cluster:AlterTopic",
                "kafka-cluster:DescribeTopicDynamicConfiguration",
                "kafka-cluster:AlterTopicDynamicConfiguration",
                "kafka-cluster:WriteData", "kafka-cluster:ReadData",
                "kafka-cluster:DescribeGroup", "kafka-cluster:AlterGroup",
                "kafka-cluster:DeleteGroup"]


def _exec_role(ctx, iam, cluster_arn_pattern: str, extra_actions=()) -> tuple[str, str]:
    """An execution role that can create ENIs AND authenticate to MSK over IAM.

    Scoped to this account's kafka-cluster resources rather than "*": MSK's IAM authorizer is the
    thing under test in the sibling negative checks, so a wildcard here would make their contrast
    meaningless if the roles ever converged.
    """
    name = ctx.unique_name("sim2real-behav-kdp-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
                          Description="sim2real kafka in-VPC data-plane executor",
                          Tags=_MANAGED_TAGS)["Role"]["Arn"]
    print(f"[ledger] created IAM role {name}")
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    iam.put_role_policy(RoleName=name, PolicyName="msk-iam-dataplane", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": _MSK_ACTIONS + list(extra_actions),
            "Resource": cluster_arn_pattern}]}))
    # IAM has no API that reports a policy has become effective, so there is nothing to poll.
    # Correctness comes entirely from the bounded retry at first USE (see _retry in the handler
    # and the CreateFunction retry in _deploy, which already sleeps 5s between attempts up to its
    # own deadline) — an extra fixed sleep here would only be a blind wait, so none is taken.
    return name, arn


def _delete_role(iam, name: str) -> None:
    try:
        for p in _paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        for pn in _paginate(iam, "list_role_policies", "PolicyNames", RoleName=name):
            iam.delete_role_policy(RoleName=name, PolicyName=pn)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchEntity":
            raise


def _make_zip(handler_src: str, vendor_kafka: bool = True) -> bytes:
    """The handler plus, when asked, a VENDORED copy of kafka-python out of this host's
    site-packages.

    kafka-python is pure Python — no compiled extension — and 0.59 MB zipped, so the whole client
    travels in the deployment package. That is what makes the in-VPC probe a real client rather
    than a hand-framed subset: `AWS_MSK_IAM` is a first-class SASL mechanism in kafka-python
    3.0.10 (it signs with botocore, which the Lambda runtime already carries), so the handshake
    the check exercises is the one a customer's client performs. Note that
    `aws-msk-iam-sasl-signer` is NOT installed on this host and is NOT needed — anything that
    imports it raises at import time on every run.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
        if vendor_kafka:
            root = os.path.dirname(kafka.__file__)
            for base, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for f in files:
                    if f.endswith((".pyc", ".pyo")):
                        continue
                    p = os.path.join(base, f)
                    zf.write(p, os.path.join("kafka", os.path.relpath(p, root)))
    return buf.getvalue()


def _lambda_client(ctx):
    """A Lambda client whose READ timeout outlives the function's own timeout.

    Not optional, and its absence is the single most confusing failure this shape has. botocore's
    default read timeout is 60 s, so a synchronous Invoke of a function that legitimately runs for
    minutes times out client-side and botocore RETRIES it — five cold-start invocations at ~61 s
    intervals, each abandoned, none of which could ever return a result. Retries are disabled for
    the same reason: an Invoke is not idempotent here, and a retried produce would double-write
    the log this check counts.
    """
    return ctx.client("lambda", config=BotoConfig(
        read_timeout=_FN_TIMEOUT_S + 60, connect_timeout=20, retries={"max_attempts": 0}))


_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions", "CreateNetworkInterface")


def _deploy(ctx, lam, role_arn: str, handler_src: str, *, net=None, prefix=None,
            env=None, vendor_kafka=True, memory=512) -> str:
    """CreateFunction (with VpcConfig when `net` is given), retried through IAM propagation, then
    wait Active.

    The retry is what makes this correct rather than flaky: a role created seconds ago is not yet
    visible to Lambda, and CreateFunction rejects it synchronously naming either the trust
    relationship or the missing EC2 action. Both are transient and neither is a verdict about any
    service.
    """
    name = ctx.unique_name(prefix or "sim2real-behav-kdp-fn-")
    kwargs = dict(FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                  Code={"ZipFile": _make_zip(handler_src, vendor_kafka)}, MemorySize=memory,
                  Timeout=_FN_TIMEOUT_S,
                  Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS})
    if net is not None:
        kwargs["VpcConfig"] = {"SubnetIds": net["subnet_ids"], "SecurityGroupIds": [net["sg_id"]]}
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = _msg_of(exc)
            transient = (_code_of(exc) == "InvalidParameterValue"
                         and any(s in msg for s in _ROLE_NOT_READY))
            if not transient or time.monotonic() >= deadline:
                raise _no_executor(
                    f"CreateFunction for {name!r} was rejected: {_code_of(exc)}: {msg}") from exc
            time.sleep(5)
    print(f"[ledger] created Lambda {name}")
    ctx.on_cleanup(lambda: _delete_fn(ctx, lam, name))
    last = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State") in ("Active", "Failed"),
                 timeout_s=300, interval_s=5)
    if last is None:
        raise AssertionError(
            f"{name} did not reach State=Active within the bounded wait (a first Hyperplane ENI "
            f"in a fresh subnet/security-group pair is the slow part)")
    if last["State"] != "Active":
        raise _no_executor(f"{name} entered State={last['State']!r}: {last.get('StateReason')!r}")
    return name


def _delete_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group its first invocation created. Returns immediately —
    Lambda releases the Hyperplane ENI asynchronously and nothing here waits for it, which is
    exactly why the network is retained rather than torn down. Not-found is the only error this
    swallows; anything else is a real failed delete and must reach the caller as a leftover."""
    for fn in (lambda: lam.delete_function(FunctionName=name),
               lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
        try:
            fn()
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFound":
                raise


#: Ops whose effect on the log is IDEMPOTENT, so re-invoking one after a transport failure cannot
#: change what the check goes on to assert. Every producing op is deliberately absent: a retried
#: produce appends the records a second time, and every count, offset and uniqueness assertion in
#: this suite would then be measuring our own retry.
_REPLAYABLE_OPS = frozenset({"selftest", "tcp_ready", "kafka_ready", "admin", "read", "offsets",
                             "group_offsets"})

#: Invoke-level failures that say nothing about the function: Lambda declining the call before it
#: runs. Observed as `ServiceException ... insufficient capacity in the region you requested`,
#: which killed two checks outright because retries are disabled (see _lambda_client).
_INVOKE_TRANSIENT = ("ServiceException", "TooManyRequestsException", "ThrottlingException",
                     "EC2ThrottledException", "ResourceNotReadyException")


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result.

    A FunctionError or a non-200 means the RUNTIME failed, not that the handler reported a
    failure — the handler never raises — so anything arriving here is the executor being unusable
    rather than a verdict about Kafka.

    Retries are handled HERE rather than by botocore, and only for `_REPLAYABLE_OPS`.
    """
    op = payload.get("op")
    deadline = time.monotonic() + 300
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                              Payload=json.dumps(payload).encode())
            break
        except ClientError as exc:
            transient = (type(exc).__name__ in _INVOKE_TRANSIENT
                         or _code_of(exc) + "Exception" in _INVOKE_TRANSIENT
                         or _code_of(exc) in _INVOKE_TRANSIENT)
            if not transient or op not in _REPLAYABLE_OPS or time.monotonic() >= deadline:
                raise _no_executor(
                    f"Invoke of {fn} for op={op!r} was refused by Lambda itself: "
                    f"{_code_of(exc)}: {_msg_of(exc)}"
                    + ("" if op in _REPLAYABLE_OPS else
                       f" — and op={op!r} is not replayable, because re-invoking it could append "
                       f"to the log a second time and invalidate every count this check asserts")) from exc
            print(f"[check] Invoke op={op!r} refused ({_code_of(exc)}); retrying a replayable op")
            # fixed-wait: backoff between retries of a transient Lambda invoke error; a shorter
            # interval would retry an already capacity-constrained control plane faster, not better.
            time.sleep(15)
    raw = resp["Payload"].read()
    if resp.get("FunctionError") or resp.get("StatusCode") != 200:
        raise _no_executor(
            f"Invoke of {fn} for op={payload.get('op')!r} returned "
            f"StatusCode={resp.get('StatusCode')!r} FunctionError={resp.get('FunctionError')!r}: "
            f"{raw[:900]!r}")
    try:
        out = json.loads(raw)
    except ValueError as exc:
        raise _no_executor(f"Invoke of {fn} returned a body that is not JSON: {raw[:800]!r}") from exc
    if not isinstance(out, dict):
        raise _no_executor(f"Invoke of {fn} returned {type(out).__name__}: {out!r}")
    # The whole handler result, not a 2.5 KB prefix: these ops return a transition ledger (every
    # generation id, every DescribeGroups snapshot, every offset) and a truncated print throws away
    # exactly the numbers a reader of the run needs in order to check the assertions by eye.
    print(f"[check] op={payload.get('op')!r} -> {json.dumps(out, default=str)[:60000]}")
    return out


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict) -> str:
    """Run the selftest and decide, BEFORE anything billable exists, whether the instrument is
    actually inside the VPC. Two claims, established separately, because collapsing them is
    exactly how a false data-plane failure gets published.

    1. THE CODE RAN. The handler returns sha256("<nonce>|<src_ip>|<rcode>") over a nonce minted
       here. A target that accepts CreateFunction and Invoke but does not execute the zip cannot
       produce it, and because the digest also covers the two network fields, a target that runs
       the code and then rewrites the response invalidates its own proof.
    2. IT RAN INSIDE OUR VPC. Two independent signals, either sufficient, and the returned string
       records which fired so the report states what was proven.
    """
    nonce = secrets.token_hex(16)
    ev = _invoke(ctx, lam, fn, {"op": "selftest", "nonce": nonce, "resolver": net["resolver"],
                               "dns_name": "amazonaws.com"})
    expect = hashlib.sha256(
        f"{nonce}|{ev.get('src_ip')}|{ev.get('resolver_rcode')}".encode()).hexdigest()
    if ev.get("nonce") != nonce or ev.get("proof") != expect:
        raise _no_executor(
            f"the invoke returned {ev!r}, which does not carry sha256 over the nonce {nonce!r} "
            f"bound to the network fields it reported (expected {expect!r}); the target accepted "
            f"CreateFunction and Invoke but did not execute the package")
    if "IMPORT FAILED" in str(ev.get("kafka_python")):
        raise _no_executor(
            f"the vendored kafka-python did not import inside the executor: "
            f"{ev['kafka_python']!r}")
    signals = []
    if ev.get("src_ip"):
        try:
            if ipaddress.ip_address(ev["src_ip"]) in ipaddress.ip_network(net["cidr"]):
                signals.append(f"ip:{ev['src_ip']} in {net['cidr']}")
        except ValueError:
            pass
    if ev.get("resolver_rcode") is not None:
        signals.append(f"dns:reply rcode={ev['resolver_rcode']} from {net['resolver']}")
    if not signals:
        raise _no_executor(
            f"neither in-VPC signal fired: the source address toward {net['resolver']} was "
            f"{ev.get('src_ip')!r} (error {ev.get('src_ip_error')!r}), not inside the executor "
            f"VPC CIDR {net['cidr']}; and the VPC resolver did not reply at all "
            f"(error {ev.get('resolver_error')!r})")
    return "; ".join(signals)


# ---- the cluster -----------------------------------------------------------------------------


def _create_serverless_cluster(ctx, msk, net: dict) -> str:
    """An MSK SERVERLESS cluster with SASL/IAM, and its delete registered before anything else.

    Serverless rather than provisioned, and that is a measurement rather than a preference. A
    provisioned cluster takes 15-30 minutes to reach ACTIVE, which uses up most of a check's time
    budget and leaves no room for the subject. Serverless reaches ACTIVE in ~150 s, and it is IAM-only — which is
    exactly the authentication the transactional and group protocols here run over. What
    Serverless cannot express is stated in each check's docstring rather than worked around.
    """
    name = ctx.unique_name("sim2real-behav-kdp-")
    arn = msk.create_cluster_v2(
        ClusterName=name,
        Serverless={"VpcConfigs": [{"SubnetIds": net["subnet_ids"],
                                    "SecurityGroupIds": [net["sg_id"]]}],
                    "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}},
        Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS})["ClusterArn"]
    # Registered IMMEDIATELY, before the ACTIVE poll: this is the only expensive thing the check
    # creates (~$450/month if stranded) and a poll that times out or an assert that fires must not
    # strand it. The VERIFIED teardown is inline at the end of run(); this is the failure-path net.
    ctx.on_cleanup(lambda: _delete_cluster(msk, arn))
    print(f"[ledger] CREATED MSK SERVERLESS CLUSTER {arn}")
    return arn


_CLUSTER_GONE = ("NotFound", "ResourceNotFound")


def _cluster_state(msk, arn: str) -> str:
    try:
        return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
    except ClientError as exc:
        return "GONE" if _code_of(exc) in _CLUSTER_GONE else f"UNKNOWN:{_code_of(exc)}"


def _delete_cluster(msk, arn: str, *, timeout_s: float = 600.0) -> str:
    """DeleteCluster, then poll until DescribeClusterV2 reports it gone; return the last state.

    run() calls this inline so a cluster that is not gone fails the check.
    """
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if _code_of(exc) not in _CLUSTER_GONE:
            print(f"[ledger] DELETE REFUSED for {arn}: {_code_of(exc)}: {_msg_of(exc)}")
            raise
        return "GONE"
    last = _poll(lambda: _cluster_state(msk, arn), lambda s: s == "GONE",
                 timeout_s=timeout_s, interval_s=2)
    return last or _cluster_state(msk, arn)


def _bootstrap(ctx, msk, arn: str) -> str:
    """The SASL/IAM bootstrap string, polled: GetBootstrapBrokers can answer before the endpoint
    is published even on a cluster that already reports ACTIVE."""
    resp = _poll(lambda: msk.get_bootstrap_brokers(ClusterArn=arn),
                 lambda r: bool(r.get("BootstrapBrokerStringSaslIam")),
                 timeout_s=180, interval_s=10)
    if resp is None:
        offered = sorted(k for k in msk.get_bootstrap_brokers(ClusterArn=arn)
                         if k.startswith("Bootstrap"))
        raise _dp_fail(
            f"{arn} is ACTIVE but never published a BootstrapBrokerStringSaslIam; the keys it "
            f"offered were {offered!r}")
    return resp["BootstrapBrokerStringSaslIam"]


def _await_data_plane(ctx, lam, fn: str, bootstrap: str) -> dict:
    """Poll until the cluster's bootstrap endpoint ACCEPTS TCP and then SERVES Kafka.

    This exists because of a measured gap that no AWS API reports. An MSK Serverless cluster
    reaches State=ACTIVE about 140 s after CreateClusterV2 and GetBootstrapBrokers answers
    immediately, but its PrivateLink endpoint does not accept a connection on 9098 for roughly
    another three to five minutes — measured across five runs in one account, a client retrying
    for 275 s after ACTIVE failed every time and a probe that kept retrying connected at ~280 s.

    Getting this wrong is misleading in both directions, and diagnosed the wrong way it looks
    exactly like a security-group defect. Polled from the runner rather than inside the Lambda so
    the wait is bounded by this check's own deadline instead of a 300 s sandbox timeout. This is a
    poll on an OBSERVABLE CONDITION — a completed TCP handshake, then a served metadata request —
    never a sleep sized to make it pass. An endpoint that never accepts is a genuine FAIL.
    """
    deadline = time.monotonic() + 900
    t0 = time.monotonic()
    tcp = {}
    while time.monotonic() < deadline:
        tcp = _invoke(ctx, lam, fn, {"op": "tcp_ready", "bootstrap": bootstrap, "timeout_s": 10})
        if tcp.get("connected"):
            print(f"[check] endpoint accepted TCP at t+{time.monotonic() - t0:.0f}s after ACTIVE: "
                  f"{tcp.get('target')!r} peer={tcp.get('peer')!r} "
                  f"tls={tcp.get('tls_version')!r}")
            break
        # fixed-wait: the gap this polls for converges on a scale of minutes (see the docstring
        # above), so a 15s cadence trades negligible detection latency for far fewer invokes.
        time.sleep(15)
    else:
        raise _dp_fail(
            f"{bootstrap} was advertised by an ACTIVE cluster but never accepted a TCP connection "
            f"in {time.monotonic() - t0:.0f}s from inside its own VPC. The executor was already "
            f"proven in-VPC, and the security group admits tcp/{_IAM_PORT} between members of the "
            f"one group both the Lambda ENI and the cluster endpoint belong to. Last: {tcp!r}")
    last = {}
    while time.monotonic() < deadline:
        last = _invoke(ctx, lam, fn, {"op": "kafka_ready", "bootstrap": bootstrap,
                                      "security_protocol": "SASL_SSL",
                                      "sasl_mechanism": "AWS_MSK_IAM"})
        if last.get("serving"):
            print(f"[check] broker served the Kafka admin protocol at "
                  f"t+{time.monotonic() - t0:.0f}s after ACTIVE "
                  f"(metadata listed {last.get('n_topics')!r} topics)")
            return dict(tcp, **{"kafka_ready": last})
        # fixed-wait: same minutes-scale convergence as the TCP barrier above.
        time.sleep(15)
    raise _dp_fail(
        f"{bootstrap} accepted TCP but never served a Kafka metadata request over SASL/IAM within "
        f"{time.monotonic() - t0:.0f}s of the cluster reporting ACTIVE, from inside its own VPC. "
        f"A socket that accepts and a broker that answers are different things and this is the "
        f"second. Last attempt: {last!r}")


def _bring_up(ctx, extra_actions=()):
    """Build the in-VPC executor, PROVE it is inside the VPC, then create the cluster.

    The order is load-bearing. Everything cheap and fully decidable happens BEFORE the create, so
    a broken instrument never bills a cluster, and once the executor is proven in-VPC a subsequent
    failure to reach the brokers is unambiguously the brokers'.
    """
    ec2, iam, msk = ctx.client("ec2"), ctx.client("iam"), ctx.client("kafka")
    lam = _lambda_client(ctx)
    net = _network(ctx, ec2)
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name, role_arn = _exec_role(ctx, iam, f"arn:aws:kafka:{ctx.region}:{account}:*",
                                     extra_actions)
    fn = _deploy(ctx, lam, role_arn, _HANDLER_SRC, net=net)
    print(f"[check] executor proven in-VPC: {_prove_executor_in_vpc(ctx, lam, fn, net)}")

    cluster_arn = _create_serverless_cluster(ctx, msk, net)
    desc = _poll(lambda: msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"],
                 lambda d: d["State"] in ("ACTIVE", "FAILED"),
                 timeout_s=900, interval_s=15)
    if desc is None:
        raise AssertionError(
            f"{cluster_arn} never left CREATING within the bounded wait; last state was "
            f"{_cluster_state(msk, cluster_arn)!r}")
    assert desc["State"] == "ACTIVE", f"cluster is {desc['State']!r}: {desc.get('StateInfo')!r}"

    bootstrap = _bootstrap(ctx, msk, cluster_arn)
    assert bootstrap and all(e.rpartition(":")[2].isdigit() for e in bootstrap.split(",")), (
        f"BootstrapBrokerStringSaslIam was {bootstrap!r}, which is not a list of host:port "
        f"brokers, so no IAM-authenticated client can connect")

    ready = _await_data_plane(ctx, lam, fn, bootstrap)
    # The listener speaks TLS; the broker's identity is not verified (SimParity CONTRACT.md,
    # Artifact TLS). The barrier's Kafka metadata fetch is what proves a broker answers.
    assert ready.get("tls_version"), (
        f"the endpoint that accepted the connection did not complete a TLS handshake "
        f"(error {ready.get('tls_error')!r})")
    return {"lam": lam, "fn": fn, "msk": msk, "iam": iam, "ec2": ec2, "net": net,
            "cluster_arn": cluster_arn, "bootstrap": bootstrap,
            "role_name": role_name, "role_arn": role_arn, "account": account}


def _teardown(ctx, up: dict) -> None:
    """Inline teardown, children before parents: every step runs, and the first failure raises.

    The tagged executor network is retained: a VPC Lambda's Hyperplane ENI holds its subnets for
    up to ~20 minutes after the function is deleted."""
    try:
        state = _delete_cluster(up["msk"], up["cluster_arn"])
        if state != "GONE":
            raise AssertionError(
                f"MSK cluster {up['cluster_arn']} is not gone after DeleteCluster (last state "
                f"{state!r}); a cluster left behind bills about $450/month")
    finally:
        try:
            _delete_fn(ctx, up["lam"], up["fn"])
        finally:
            _delete_role(up["iam"], up["role_name"])


def _create_topic(ctx, lam, fn, base, *, partitions=1, topic_configs=None):
    """Create the topic through the native AdminClient and assert the broker really lists it."""
    admin = _invoke(ctx, lam, fn, dict(base, op="admin", partitions=partitions,
                                       topic_configs=topic_configs))
    if not admin.get("ok"):
        raise _dp_fail(
            f"the AdminClient could not create {base['topic']!r} over SASL/IAM on "
            f"{base['bootstrap']!r} (stage {admin.get('stage')!r}): {admin.get('error')!r}; "
            f"connect attempts {admin.get('connect_attempts')!r}")
    assert base["topic"] in admin["topics"], (
        f"CreateTopics reported success but the broker lists "
        f"{sorted(admin['topics'])[:10]!r}, which does not include {base['topic']!r}")
    return admin


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(s):
    return None if s is None else base64.b64decode(s)


def _values(records) -> list[bytes]:
    return [_unb64(r["value"]) for r in records]


def _coords(records) -> list[tuple]:
    return [(r["partition"], r["offset"]) for r in records]


# 5 records appended inside a transaction that is then ABORTED, and 5 appended inside one that is
# COMMITTED. Kept equal and small so every offset below can be written out by hand: the aborted
# batch takes 0-4, the ABORT control batch takes 5, the committed batch takes 6-10 and the COMMIT
# control batch takes 11 — so the high watermark ends at 12 for ten records.
_N_ABORTED = 5
_N_COMMITTED = 5
_ABORT_MARKER_OFFSET = _N_ABORTED
_HWM_AFTER = _N_ABORTED + 1 + _N_COMMITTED + 1


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """An aborted transaction's records are INVISIBLE to a read_committed consumer, VISIBLE to a
    read_uncommitted one, and never reoccupy their offsets; `ListOffsets(LATEST)` answers
    differently per isolation level for the same partition at the same instant — measured live.
    """
    up = None
    try:
        up = _bring_up(ctx, extra_actions=[
            # Transactions are gated by three actions this check's role would not otherwise ask
            # for. InitProducerId is authorized at CLUSTER scope, and the transactional-id
            # resource is a separate ARN type under the same account/region wildcard.
            "kafka-cluster:WriteDataIdempotently",
            "kafka-cluster:AlterTransactionalId",
            "kafka-cluster:DescribeTransactionalId",
        ])
        lam, fn = up["lam"], up["fn"]
        base = {"bootstrap": up["bootstrap"], "security_protocol": "SASL_SSL",
                "sasl_mechanism": "AWS_MSK_IAM", "snap_poll_s": 15}
        # One partition: a total order makes the abort/commit interleave and every offset below
        # unambiguous. Two topics, because the fencing arm appends a record that is then aborted,
        # and letting it share this log would perturb the offset arithmetic that is the subject.
        topic = ctx.unique_name("sim2real-behav-kdp-txn-")
        fence_topic = ctx.unique_name("sim2real-behav-kdp-fen-")
        _create_topic(ctx, lam, fn, dict(base, topic=topic), partitions=1)
        _create_topic(ctx, lam, fn, dict(base, topic=fence_topic), partitions=1)

        # NUL and 0xff bytes in every payload: an emulator that round-trips through a text codec
        # mangles exactly these and an ASCII payload would not notice.
        aborted = [b"sim2real-ABORTED-%d-\x00\xff" % i for i in range(_N_ABORTED)]
        committed = [b"sim2real-COMMITTED-%d-\x00\xff" % i for i in range(_N_COMMITTED)]

        cyc = _invoke(ctx, lam, fn, dict(
            base, op="txn_cycle", topic=topic,
            transactional_id=ctx.unique_name("sim2real-kdp-tid-"),
            transaction_timeout_ms=180000,
            aborted_records=[[None, _b64(v)] for v in aborted],
            committed_records=[[None, _b64(v)] for v in committed]))
        if not cyc.get("ok"):
            raise _dp_fail(
                f"the transactional cycle on {topic!r} failed at stage {cyc.get('stage')!r}: "
                f"{cyc.get('type')!r} {cyc.get('error')!r} "
                f"kafka_error={cyc.get('kafka_error')!r} "
                f"cause={cyc.get('cause_kafka_error')!r}; tb={cyc.get('traceback')!r}")

        # ---- the acks: the records were physically APPENDED before their fate was decided ----
        ab_meta = cyc["aborted_batch"]["metadata"]
        assert not cyc["aborted_batch"]["errors"], (
            f"the batch that was going to be aborted did not even land: "
            f"{cyc['aborted_batch']['errors']!r}")
        assert [m["offset"] for m in ab_meta] == list(range(_N_ABORTED)), (
            f"the broker acked the to-be-aborted batch at offsets "
            f"{[m['offset'] for m in ab_meta]!r}; a fresh single-partition log must place "
            f"{_N_ABORTED} records at {list(range(_N_ABORTED))!r}")
        cm_meta = cyc["committed_batch"]["metadata"]
        assert not cyc["committed_batch"]["errors"], (
            f"the committed batch did not land: {cyc['committed_batch']['errors']!r}")
        # THE control-batch assertion. The committed batch starts at 6, not 5, because the ABORT
        # marker physically occupies offset 5. An emulator that filters aborted records out of a
        # list, rather than appending a marker to a log, gives 5 here.
        assert [m["offset"] for m in cm_meta] == list(
            range(_ABORT_MARKER_OFFSET + 1, _ABORT_MARKER_OFFSET + 1 + _N_COMMITTED)), (
            f"the committed batch was acked at offsets {[m['offset'] for m in cm_meta]!r}; it must "
            f"begin at {_ABORT_MARKER_OFFSET + 1} because the ABORT control batch consumed offset "
            f"{_ABORT_MARKER_OFFSET} of the log")

        # ---- the in-flight snapshot: one log, two answers, one isolation flag apart ----
        inf = cyc["inflight"]
        for label in ("offsets", "read_committed", "read_uncommitted"):
            assert inf[label].get("ok"), (
                f"the in-flight {label} probe failed at stage {inf[label].get('stage')!r}: "
                f"{inf[label].get('error')!r}")
        inf_rc, inf_ru = inf["read_committed"], inf["read_uncommitted"]
        assert inf_rc["records"] == [], (
            f"a read_committed consumer read {_values(inf_rc['records'])!r} at offsets "
            f"{[r['offset'] for r in inf_rc['records']]!r} from a partition whose only records sit "
            f"inside an OPEN transaction. It polled {inf_rc.get('polls')!r} times over the whole "
            f"budget and must see none of them")
        assert _values(inf_ru["records"]) == aborted, (
            f"a read_uncommitted consumer read {_values(inf_ru['records'])!r} while the "
            f"transaction was open; it must see all {_N_ABORTED} uncommitted records, in order, "
            f"byte-identically")
        inf_off = inf["offsets"]["offsets"]
        assert inf_off["read_uncommitted"]["latest"] == {"0": _N_ABORTED}, (
            f"ListOffsets(LATEST, read_uncommitted) answered {inf_off['read_uncommitted']['latest']!r} "
            f"with {_N_ABORTED} flushed records in an open transaction; the HIGH WATERMARK must be "
            f"{_N_ABORTED}")
        assert inf_off["read_committed"]["latest"] == {"0": 0}, (
            f"ListOffsets(LATEST, read_committed) answered {inf_off['read_committed']['latest']!r} "
            f"for the same partition at the same instant; the LAST STABLE OFFSET must still be 0, "
            f"because nothing has been committed. Identical request coordinates, one isolation "
            f"flag apart, and the two numbers must differ — this is the assertion no recorded "
            f"response can satisfy")

        # ---- the final snapshot: the abort is permanent and the offsets it took are not reused ----
        fin = cyc["final"]
        for label in ("offsets", "read_committed", "read_uncommitted"):
            assert fin[label].get("ok"), (
                f"the final {label} probe failed at stage {fin[label].get('stage')!r}: "
                f"{fin[label].get('error')!r}")
        fin_rc, fin_ru = fin["read_committed"], fin["read_uncommitted"]
        assert _values(fin_rc["records"]) == committed, (
            f"a read_committed consumer read {_values(fin_rc['records'])!r}; it must read exactly "
            f"the {_N_COMMITTED} committed values, in order and byte-identically, and nothing else")
        assert not set(aborted) & set(_values(fin_rc["records"])), (
            f"aborted values {sorted(set(aborted) & set(_values(fin_rc['records'])))!r} were "
            f"delivered to a read_committed consumer")
        assert [r["offset"] for r in fin_rc["records"]] == list(
            range(_ABORT_MARKER_OFFSET + 1, _ABORT_MARKER_OFFSET + 1 + _N_COMMITTED)), (
            f"the read_committed records came back at offsets "
            f"{[r['offset'] for r in fin_rc['records']]!r}; they must sit at "
            f"{list(range(_ABORT_MARKER_OFFSET + 1, _ABORT_MARKER_OFFSET + 1 + _N_COMMITTED))!r}, "
            f"which is NOT contiguous with offset 0 — the aborted records still occupy 0-"
            f"{_N_ABORTED - 1} and were not compacted away")
        assert _values(fin_ru["records"]) == aborted + committed, (
            f"a read_uncommitted consumer read {_values(fin_ru['records'])!r}; it must read all "
            f"{_N_ABORTED + _N_COMMITTED} records, aborted ones included")
        expect_ru_offsets = list(range(_N_ABORTED)) + list(
            range(_ABORT_MARKER_OFFSET + 1, _ABORT_MARKER_OFFSET + 1 + _N_COMMITTED))
        assert [r["offset"] for r in fin_ru["records"]] == expect_ru_offsets, (
            f"the read_uncommitted offsets were {[r['offset'] for r in fin_ru['records']]!r}; they "
            f"must be {expect_ru_offsets!r} — a GAP at offset {_ABORT_MARKER_OFFSET}, which is the "
            f"ABORT control batch occupying a real offset that carries no record")
        fin_off = fin["offsets"]["offsets"]
        assert fin_off["read_uncommitted"]["latest"] == {"0": _HWM_AFTER}, (
            f"the high watermark is {fin_off['read_uncommitted']['latest']!r} after "
            f"{_N_ABORTED + _N_COMMITTED} records; it must be {_HWM_AFTER} — the two transaction "
            f"markers each consumed an offset, so the log end exceeds the record count")
        assert fin_off["read_committed"]["latest"] == {"0": _HWM_AFTER}, (
            f"the last stable offset is {fin_off['read_committed']['latest']!r}; once the second "
            f"transaction has committed it must have caught up to the high watermark "
            f"{_HWM_AFTER}")

        # ---- the refusal arm: a second producer on the same transactional id FENCES the first ----
        fenced_value = b"sim2real-FENCED-\x00\xff"
        control_value = b"sim2real-FENCE-CONTROL-\x00\xff"
        fen = _invoke(ctx, lam, fn, dict(
            base, op="txn_fence", topic=fence_topic,
            transactional_id=ctx.unique_name("sim2real-kdp-ftid-"),
            control_transactional_id=ctx.unique_name("sim2real-kdp-ctid-"),
            fenced_records=[[None, _b64(fenced_value)]],
            control_records=[[None, _b64(control_value)]]))
        if not fen.get("ok"):
            raise _dp_fail(
                f"the fencing arm on {fence_topic!r} failed at stage {fen.get('stage')!r}: "
                f"{fen.get('type')!r} {fen.get('error')!r}; tb={fen.get('traceback')!r}")
        assert fen.get("p2_initialized") is True, (
            "a second producer holding the same transactional id could not complete "
            "InitProducerId, so no epoch bump happened and the fencing arm proved nothing")
        p1c = fen["p1_commit"]
        assert p1c.get("refused") is True, (
            f"the FENCED producer's commit_transaction() SUCCEEDED ({p1c!r}). A second "
            f"InitProducerId on the same transactional id must bump the producer epoch and make "
            f"the first producer's commit impossible")
        assert p1c.get("kafka_error") == "PRODUCER_FENCED", (
            f"the fenced commit was refused with kafka_error={p1c.get('kafka_error')!r} "
            f"errno={p1c.get('kafka_errno')!r} (python class {p1c.get('type')!r}); the Kafka "
            f"protocol error for a bumped epoch is PRODUCER_FENCED")
        assert p1c.get("kafka_errno") == 90, (
            f"the fenced commit reported protocol errno {p1c.get('kafka_errno')!r}; "
            f"PRODUCER_FENCED is 90, and a class name is not an error code")
        ffin = fen["final"]
        for label in ("offsets", "read_committed", "read_uncommitted"):
            assert ffin[label].get("ok"), (
                f"the post-fence {label} probe failed: {ffin[label].get('error')!r}")
        # Effect-absent: whatever the fenced producer appended never becomes committed.
        assert _values(ffin["read_committed"]["records"]) == [control_value], (
            f"read_committed on the fencing topic returned "
            f"{_values(ffin['read_committed']['records'])!r}; only the CONTROL record — written "
            f"under a fresh transactional id and committed — may be visible, and the fenced "
            f"record must never be")
        assert fenced_value not in _values(ffin["read_committed"]["records"]), (
            f"the fenced producer's record {fenced_value!r} became visible to a read_committed "
            f"consumer even though its commit was refused")
        # ...but it IS still in the log, which is what makes the absence above a filtering
        # decision rather than a write that never happened.
        assert _values(ffin["read_uncommitted"]["records"]) == [fenced_value, control_value], (
            f"read_uncommitted on the fencing topic returned "
            f"{_values(ffin['read_uncommitted']['records'])!r}; the fenced record was physically "
            f"appended and acked, so it must still be there")
        assert fen["control_committed"] is True and not fen["control_batch"]["errors"], (
            f"the control producer on a FRESH transactional id could not commit: "
            f"{fen['control_batch']['errors']!r} — so the refusal above cannot be attributed to "
            f"the epoch rather than to a coordinator that stopped serving")
    except BaseException as subject:
        # The subject's failure stays primary; a teardown failure rides along as a note.
        if up is not None:
            try:
                _teardown(ctx, up)
            except Exception as td:
                subject.add_note(f"teardown also failed: {td!r}")
        raise
    else:
        if up is not None:
            _teardown(ctx, up)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
