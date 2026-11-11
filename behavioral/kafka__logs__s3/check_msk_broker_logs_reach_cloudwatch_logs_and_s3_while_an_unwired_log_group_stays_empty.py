"""msk-broker-logs-reach-cloudwatch-logs-and-s3-while-an-unwired-log-group-stays-empty."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import secrets
import time
import zipfile

import kafka  # noqa: F401 — vendored INTO the executor package; see _make_zip
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, ConnectionClosedError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "msk-broker-logs-reach-cloudwatch-logs-and-s3-while-an-unwired-log-group-stays-empty"
GROUP = 'native-dataplane'
SERVICES = ['kafka', 'logs', 's3']

# PLAINTEXT, not TLS, and unauthenticated. The subject is whether a broker HONOURS a cluster
# Configuration; transit encryption and authentication are separate concerns with their own checks
# and folding them in here would report a handshake failure as a configuration finding.
_KAFKA_PORT = 9092
_API_VERSIONS_API_KEY = 18

# One broker per subnet is required — MSK rejects a NumberOfBrokerNodes that is not a multiple of
# the client-subnet count — and two is the floor for a default.replication.factor that means
# anything.
_BROKER_TYPE = "kafka.t3.small"
_KAFKA_VERSION = "3.9.x"
_BROKERS = 2

# The S3 prefix the cluster is told to write under. Named, not empty, so the "at least one object
# under the prefix MSK was given" assertion is about the configuration rather than about the bucket.
_S3_PREFIX = "sim2real-broker-logs"

_TOPIC_PARTITIONS = 3
_RECORDS = 20

# How the wired group's measured first-event latency L sizes the minimum absence window for the
# UNWIRED group: long enough that a correct-but-slower delivery path is not scored as having
# blocked. Floored so a suspiciously fast L cannot produce a window of a few seconds.
_ABSENCE_MULTIPLE = 3
_ABSENCE_FLOOR_S = 180.0

# The bound on waiting for a broker log event emitted after the absence observation began to reach
# the wired group, the positive control that ends the negative leg.
_CONTROL_TIMEOUT_S = 900.0

# A DELIVERY fidelity marker, distinct from DATAPLANE_MARKER: "the write happened and nothing was
# delivered" and "no broker answered" are different findings and must not be collapsed. The failure
# messages here interpolate destination names rather than errno text, so this exists to keep an
# absent delivery from being triaged as an environment problem.
DELIVERY_MARKER = "DELIVERY_UNIMPLEMENTED"

# MSK rejects a create it cannot place. Distinguished from a fidelity failure because "this region
# has no t3.small capacity right now" is not a statement about any target.
_MSK_NO_CAPACITY = frozenset({"TooManyRequests", "ServiceUnavailable", "InternalServerError"})

_FN_TIMEOUT_S = 300

# The reusable in-VPC executor network. VPC + subnets + security group are all FREE, and a Lambda
# with VpcConfig leaves a Hyperplane ENI holding the subnet for up to ~20 minutes after the
# function is deleted. So the network is looked up by this tag and REUSED rather than rebuilt and
# torn down: the ENI drain then blocks nothing, and Lambda reuses the ENI for the same
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
# synchronously.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# A native data-plane FAIL marker, load-bearing because the failure messages below interpolate
# errno text and `Connection refused` / `timed out` would otherwise be mistaken for a plain
# connectivity gap rather than a graded fidelity failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


# ===== the in-VPC executor =====================================================================

_HANDLER_SRC = r'''"""In-VPC MSK probe: vendored kafka-python plus a hand-framed SASL prober."""
import base64, hashlib, json, os, random, socket, ssl, struct, sys, time, traceback


def _route_source_ip(host, port):
    """The source address the kernel WOULD use to reach host:port. connect() on a UDP socket sends
    no packet — it only performs a route lookup — so this is free and cannot be satisfied by
    anything listening at the far end."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, int(port)))
        return s.getsockname()[0]
    finally:
        s.close()


def _dns_query(resolver, name, timeout=3.0):
    """One hand-framed DNS A query straight at `resolver`, returning (rcode, ancount).

    Hand-framed rather than socket.gethostbyname because THE RESOLVER IS THE SUBJECT: this must go
    to the address the caller nominated (the VPC CIDR base + 2, where the Route 53 Resolver lives)
    and not to whatever /etc/resolv.conf says. That address answers ONLY from inside that VPC.
    Validated on source address, the QR bit and our transaction id, because the socket is
    unconnected and the kernel would otherwise hand back a datagram from ANY source as proof.
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
    return {"ok": True, "nonce": nonce,
            "proof": hashlib.sha256(("%s|%s|%s" % (nonce, src_ip, rcode)).encode()).hexdigest(),
            "src_ip": src_ip, "src_ip_error": src_err, "resolver": resolver,
            "resolver_rcode": rcode, "resolver_ancount": ancount, "resolver_error": dns_err,
            "kafka_python": kver,
            "region_env": os.environ.get("AWS_REGION"), "python": sys.version.split()[0]}


def _first_broker(bootstrap):
    host, _, port = bootstrap.split(",")[0].rpartition(":")
    return host, int(port)


def _tls_context():
    """TLS without verifying the broker's identity (SimParity CONTRACT.md, Artifact TLS)."""
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _tcp_ready(event):
    """ONE short TCP connect to the bootstrap endpoint, plus a TLS handshake.

    A single attempt with no internal retry: the caller polls this from OUTSIDE the Lambda, so the
    wait is bounded by the CHECK's deadline and every attempt appears in the run's output.
    """
    host, port = _first_broker(event["bootstrap"])
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=float(event.get("timeout_s", 10)))
    except Exception as exc:
        return {"ok": True, "connected": False, "seconds": round(time.monotonic() - t0, 2),
                "target": "%s:%s" % (host, port),
                "error": "%s: errno=%s %s" % (type(exc).__name__,
                                              getattr(exc, "errno", None), exc)}
    out = {"ok": True, "connected": True, "seconds": round(time.monotonic() - t0, 2),
           "target": "%s:%s" % (host, port), "peer": s.getpeername()[0]}
    if not event.get("tls", False):
        # The listener under test is PLAINTEXT, so there is no certificate to fetch. Wrapping it in
        # TLS anyway would leave a `tls_error` in the response that reads like a defect and is not
        # one; the check asserts on the hand-framed ApiVersions exchange instead.
        try:
            s.close()
        except Exception:
            pass
        return out
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


# ---- the hand-framed ApiVersions prober ------------------------------------------------------
#
# Hand-framed rather than driven through kafka-python because it is the ONE exchange that separates
# "a socket accepted" from "an Apache Kafka broker is behind it", and kafka-python collapses a
# non-Kafka peer into the same connection error as a closed port. The api-key table it returns is
# also the only place the broker states its own protocol surface.


def _frame(api_key, api_version, correlation_id, body, client_id="sim2real-cfg-probe"):
    """A Kafka request: INT32 length, then request header v1, then the body."""
    cid = client_id.encode()
    header = (struct.pack(">hhi", api_key, api_version, correlation_id)
              + struct.pack(">h", len(cid)) + cid)
    payload = header + body
    return struct.pack(">i", len(payload)) + payload


def _read_exactly(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("only %d of %d bytes arrived before the deadline" % (len(buf), n))
        sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("broker closed the connection after %d of %d bytes"
                                  % (len(buf), n))
        buf += chunk
    return buf


def _api_versions(event):
    """ApiVersions v0 straight at the PLAINTEXT listener, before any client library is involved.

    Returns raw fields only; every assertion lives in the check.
    """
    host, port = _first_broker(event["bootstrap"])
    deadline = time.monotonic() + float(event.get("timeout_s", 20))
    out = {"ok": False, "stage": "connect", "target": "%s:%s" % (host, port)}
    try:
        sock = socket.create_connection((host, port), timeout=15)
    except Exception as exc:
        out["error"] = "%s: errno=%s %s" % (type(exc).__name__, getattr(exc, "errno", None), exc)
        return out
    try:
        out["stage"] = "api_versions"
        sock.sendall(_frame(event["api_versions_api_key"], 0, 1, b""))
        (size,) = struct.unpack(">i", _read_exactly(sock, 4, deadline))
        assert 0 < size <= 8 << 20, "implausible response size %r" % (size,)
        payload = _read_exactly(sock, size, deadline)
        (corr,) = struct.unpack(">i", payload[:4])
        body = payload[4:]
        out["correlation_id"] = corr
        (err, count) = struct.unpack_from(">hi", body, 0)
        out["error_code"] = err
        off, versions = 6, {}
        for _ in range(max(0, count)):
            key, lo, hi = struct.unpack_from(">hhh", body, off)
            off += 6
            versions[key] = [lo, hi]
        out["n_api_keys"] = len(versions)
        out["api_keys"] = sorted(versions)
        out["ok"] = True
        out["stage"] = None
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        out["traceback"] = traceback.format_exc()[-800:]
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return out


# ---- the real client ---------------------------------------------------------------------------


def _conn(event):
    """kafka-python connection kwargs. PLAINTEXT with no sasl_mechanism: the listener is
    unauthenticated on purpose (see _KAFKA_PORT). api_version_auto_timeout_ms is NOT a valid config
    for KafkaAdminClient in kafka-python 3.0.10 and raises KafkaConfigurationError, so it is never
    passed."""
    return {"bootstrap_servers": event["bootstrap"].split(","),
            "security_protocol": event.get("security_protocol", "PLAINTEXT"),
            "request_timeout_ms": int(event.get("request_timeout_ms", 60000))}


def _connect_errors():
    """Only the errors a not-yet-accepting broker actually raises. Deliberately NOT `Exception`: a
    KafkaConfigurationError is deterministic and retrying it burns the whole budget to reach the
    same answer. Resolved by NAME because the names moved — `NoBrokersAvailable` does not exist in
    kafka-python 3.0.10."""
    import kafka.errors as ke
    wanted = ("KafkaConnectionError", "KafkaTimeoutError", "MetadataEmptyBrokerList",
              "NodeNotReadyError", "NoBrokersAvailable")
    found = tuple(getattr(ke, n) for n in wanted if hasattr(ke, n))
    assert len(found) >= 2, "kafka.errors exposes none of %r" % (wanted,)
    return found + (OSError,)


def _retry(fn, budget_s):
    """Call fn() until it stops raising a CONNECTION error or budget_s runs out. Every attempt is
    reported so a genuine failure names what was tried."""
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


def _kafka_ready(event):
    """ONE short attempt at a real Kafka ADMIN PROTOCOL call. A completed TCP handshake is not
    enough: after tcp_ready succeeds, KafkaAdminClient can still connect and then have its first
    request time out. The operation is a METADATA fetch (list_topics), deliberately not
    describe_cluster — kafka-python 3.0.10's describe_cluster() raises KeyError 'endpoint_type'
    against MSK Serverless, which is a client/broker incompatibility, not a readiness signal."""
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
    """Create `topic` over the native admin protocol with the mechanism the caller names, then read
    the broker's own view back.

    `refusal_expected` inverts the CONNECT handling only: when the caller expects the mechanism to
    be refused, a connect failure is the RESULT and is reported with its class and message rather
    than retried to the end of the budget. Nothing else changes, so the two arms issue the
    identical CreateTopics.
    """
    from kafka.admin import (ConfigResource, ConfigResourceType, KafkaAdminClient, NewTopic)
    from kafka.errors import TopicAlreadyExistsError
    out = {"ok": False, "stage": "connect", "sasl_mechanism": event.get("sasl_mechanism")}
    budget = 20 if event.get("refusal_expected") else budget_s
    try:
        admin, out["connect_attempts"] = _retry(lambda: KafkaAdminClient(**_conn(event)), budget)
    except Exception as exc:
        out["connect_failed"] = True
        out["error_class"] = type(exc).__name__
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
        out["kafka_errno"] = getattr(exc, "errno", None)
        return out
    try:
        out["stage"] = "create_topic"
        topic = event["topic"]

        def _create():
            try:
                # -1 for either value is the Apache Kafka sentinel for "use the broker default",
                # and passing it is the whole point of this check. See H2.
                admin.create_topics([NewTopic(
                    name=topic, num_partitions=int(event.get("partitions", -1)),
                    replication_factor=int(event.get("replication", -1)),
                    topic_configs=event.get("topic_configs") or None)])
            except TopicAlreadyExistsError:
                out["already_existed"] = True

        try:
            _, out["create_attempts"] = _retry(_create, min(budget, 180))
        except Exception as exc:
            out["create_failed"] = True
            out["error_class"] = type(exc).__name__
            out["error"] = "%s: %s" % (type(exc).__name__, exc)
            out["kafka_errno"] = getattr(exc, "errno", None)
            return out
        # CreateTopicsResponse only says the broker ACCEPTED the create. describe_topics is a
        # DIRECT query and is the reliable witness; list_topics() reads the client's CACHED
        # metadata and has been measured returning [] for a topic that demonstrably existed.
        out["stage"] = "wait_for_topics"
        try:
            admin.wait_for_topics([topic], timeout_ms=int(event.get("topic_wait_ms", 60000)))
            out["topic_ready"] = True
        except Exception as exc:
            out["topic_ready"] = False
            out["wait_for_topics_error"] = "%s: %s" % (type(exc).__name__, exc)
        # DescribeTopics is a DIRECT query for this topic; list_topics() reads the client's CACHED
        # metadata and has been measured returning [] for a topic that demonstrably existed. The
        # per-partition replica list comes from here too, which is what makes the
        # default.replication.factor leg gradeable at all.
        out["stage"] = "describe_topics"
        described = admin.describe_topics(topics=[topic])
        # kafka-python 3.0.11's admin responses are the Kafka protocol's OWN field names run
        # through to_dict() (see MetadataResponse.json): a partition is keyed `partition_index`,
        # not `partition`, and its replica set is `replica_nodes`, not `replicas`. Both of those
        # wrong names silently returned None from every .get(), and `sorted([None, None, None])`
        # (three partitions, three Nones) raised — measured on a real MSK cluster's admin protocol
        # response, not a guess.
        out["described"] = [
            {"name": t.get("name"), "error_code": t.get("error_code"),
             "n_partitions": len(t.get("partitions") or []),
             "partition_ids": sorted(p.get("partition_index")
                                     for p in (t.get("partitions") or [])),
             "replica_counts": sorted(len(p.get("replica_nodes") or [])
                                      for p in (t.get("partitions") or []))}
            for t in (described or [])]
        out["stage"] = "list_topics"
        out["topics"] = sorted(admin.list_topics())
        # The BROKER's own effective configuration. This is the read that says the cluster
        # Configuration reached the broker rather than merely being stored by the control plane.
        # Isolated so a surprise in the response shape (see H3) does not cost the partition-count
        # legs, which are the subject.
        out["stage"] = "describe_broker_configs"
        try:
            dc = admin.describe_cluster()
            ids = sorted(str(b.get("node_id")) for b in dc.get("brokers") or [])
            out["broker_ids"] = ids
            out["controller_id"] = dc.get("controller_id")
            out["cluster_id"] = dc.get("cluster_id")
        except Exception as exc:
            ids = []
            out["describe_cluster_error"] = "%s: %s" % (type(exc).__name__, exc)
        wanted = list(event.get("broker_config_names") or [])
        out["broker_configs"] = {}
        for bid in ids:
            try:
                # config_filter='all' rather than the default 'modified', so a property that happens
                # to equal the Apache default is still reported instead of silently missing.
                raw = admin.describe_configs(
                    [ConfigResource(ConfigResourceType.BROKER, bid)], config_filter="all")
                entries = (raw.get("broker") or {}).get(bid) or {}
                out["broker_configs"][bid] = {
                    name: (cfg.get("value") if isinstance(cfg, dict) else cfg)
                    for name, cfg in entries.items() if not wanted or name in wanted}
            except Exception as exc:
                out["broker_configs"][bid] = {"__error__": "%s: %s" % (type(exc).__name__, exc)}
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


def _produce(event, budget_s):
    """Produce records and return the metadata the BROKER assigned to each one, or the per-record
    Kafka protocol error. A per-record failure is a RETURN VALUE, never a raise: the errno is what
    the caller asserts, and an exception here would arrive as a FunctionError the caller never
    reads."""
    from kafka import KafkaProducer
    out = {"ok": False, "stage": "connect"}
    kw = _conn(event)
    # acks='all', not the default: with acks=1 the leader appends and acks at once but the HIGH
    # WATERMARK does not advance until the replica has caught up, so an acks=1 produce followed by a
    # fetch legitimately returns an offset and ZERO readable records.
    kw["acks"] = "all"
    # A produce to a topic that does not exist blocks in metadata discovery for max_block_ms before
    # failing, so the auto-create sub-probe needs this short and stated rather than the 60 s default.
    kw["max_block_ms"] = int(event.get("max_block_ms", 30000))
    try:
        prod, out["connect_attempts"] = _retry(lambda: KafkaProducer(**kw), budget_s)
    except Exception as exc:
        out["stage"] = "connect"
        out["errors"] = [{"i": -1, "type": type(exc).__name__, "error": str(exc),
                          "kafka_error": getattr(exc, "message", None),
                          "kafka_errno": getattr(exc, "errno", None)}]
        return out
    try:
        out["stage"] = "send"
        futures = [prod.send(event["topic"], key=None, value=base64.b64decode(v))
                   for v in event["values"]]
        try:
            prod.flush(timeout=60)
        except Exception as exc:
            out["flush_error"] = "%s: %s" % (type(exc).__name__, exc)
        meta, errors = [], []
        for i, f in enumerate(futures):
            try:
                m = f.get(timeout=60)
                meta.append({"i": i, "partition": m.partition, "offset": m.offset})
            except Exception as exc:
                errors.append({"i": i, "type": type(exc).__name__, "error": str(exc),
                               "kafka_error": getattr(exc, "message", None),
                               "kafka_errno": getattr(exc, "errno", None)})
        out["metadata"] = meta
        out["errors"] = errors
        out["ok"] = not errors
        out["stage"] = None if not errors else "send"
    finally:
        try:
            prod.close(timeout=15)
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
        if op == "api_versions":
            return _api_versions(event)
        fn = {"admin": _admin, "produce": _produce}.get(op)
        if fn is not None:
            return fn(event, budget)
        return {"ok": False, "stage": "dispatch", "error": "unknown op %r" % (op,)}
    except Exception as exc:
        return {"ok": False, "stage": "handler", "type": type(exc).__name__,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "traceback": traceback.format_exc()[-1500:]}
'''


# ===== helpers ==================================================================================


def _dp_fail(msg: str) -> AssertionError:
    """The native data-plane fidelity FAIL, distinct from a connectivity failure. Returned rather
    than raised so a call site keeps its `from exc` chaining."""
    return AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _no_executor(msg: str):
    """The in-VPC executor is unusable, so this run measured nothing."""
    return AssertionError(f"the in-VPC executor is unusable, so this run measured nothing: {msg}")


def _code_of(exc: ClientError) -> str:
    """The error code with its modelled Exception/Fault suffix stripped. EVERY comparison against
    this must use the BASE form: `NotFoundException` arrives here as `NotFound`."""
    code = exc.response.get("Error", {}).get("Code") or ""
    for suffix in ("Exception", "Fault"):
        if code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _msg_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _paginate(client, op: str, key: str, **kwargs):
    """Every page of `op`, flattened on `key`. Paginated so a resource is not missed behind
    other resources in the account."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 — no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _poll(probe, predicate, *, timeout_s: float, interval_s: float):
    """Poll `probe` until `predicate`. Returns the last observation, or None on timeout — returns
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
    """Does sg_id already allow tcp/`port` TO/FROM ITSELF? Matched on the GROUP PAIR, not on a
    CIDR: a 0.0.0.0/0 rule on the data port would let the exchange succeed without proving the
    packets travelled between ENIs we attached."""
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
    network paths must guarantee it, not just the create path. The EGRESS half is not padding: a
    brand-new group gets AWS's default allow-all egress, so a freshly CREATED network works; if
    something later revokes it, the RETAINED group can receive on the data port and send nothing —
    a failure invisible to the in-VPC control step, because both of its proofs bypass security
    groups."""
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
        f"{'egress to' if egress else 'ingress from'} itself after authorizing; the exchange "
        f"below could not distinguish this from a broker that refuses every mechanism")


def _usable_azs(ec2, want: int = 2) -> list[str]:
    """`want` availability zones this account can actually place a subnet in. Never a hardcoded
    zone name — AZ names are per-account aliases for different physical zones."""
    zones = _paginate(ec2, "describe_availability_zones", "AvailabilityZones", Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}])
    names = sorted(z["ZoneName"] for z in zones)
    assert len(names) >= want, (
        f"{ec2.meta.region_name!r} offers only {names!r} available non-opt-in zones, and MSK "
        f"needs {want} in distinct zones; this region cannot host the executor")
    return names[:want]


def _ensure_subnets(ec2, vpc_id: str, cidr: str, existing: list, want: int = 2) -> list[str]:
    """The executor subnets, completed to `want` DISTINCT availability zones. Counting ZONES rather
    than subnets is the point: a predecessor that died between the two creates leaves exactly one
    tagged subnet, and treating any non-empty set as complete would reuse that single-AZ network
    forever."""
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
            # Two checks racing in the same account derive the same deterministic CIDR, so the
            # loser adopts the winner's subnets rather than failing the run.
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
    """The executor security group, created if absent, always carrying the self rules. The
    self-reference is a second control: both the Lambda ENI and the cluster's endpoints sit in this
    ONE group, and the only rule admits tcp/9092 from members of the group itself — so a successful
    connect PROVES the packets originated from an ENI in the group we attached."""
    sg_id = (sorted(g["GroupId"] for g in existing)[0] if existing
             else ec2.create_security_group(
                 GroupName=ctx.unique_name("sim2real-behav-kdp-sg-"),
                 Description="sim2real kafka in-VPC executor: Lambda ENI + MSK, self-referencing",
                 VpcId=vpc_id,
                 TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
             )["GroupId"])
    _ensure_rule(ec2, sg_id, _KAFKA_PORT, egress=False)
    _ensure_rule(ec2, sg_id, _KAFKA_PORT, egress=True)
    return sg_id


def _network(ctx, ec2) -> dict:
    """The tagged executor VPC, COMPLETED where it is partial, created only if none exists.

    Created in-check and idempotently, never discovered: a fresh account may have no
    default VPC.

    Lowest VpcId wins if two exist, so a duplicate from a racing run is inert rather than flapping.
    Nothing here is registered for cleanup, deliberately: a Lambda with VpcConfig leaves a
    requester-managed Hyperplane ENI holding the subnet for up to ~20 minutes after the function is
    deleted, so an ephemeral network turns every teardown into a DependencyViolation retry loop
    that reclaims nothing. VPC, subnets and security groups are free.
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


def _exec_role(ctx, iam) -> str:
    """An execution role that can create ENIs and write its own logs, and nothing else."""
    name = ctx.unique_name("sim2real-behav-kdp-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
                          Description="sim2real kafka in-VPC data-plane executor",
                          Tags=_MANAGED_TAGS)["Role"]["Arn"]
    print(f"[ledger] created IAM role {name}")
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    # No kafka-cluster: statements, deliberately. The listener is PLAINTEXT and unauthenticated, so
    # MSK's IAM authorizer is not in the path at all — granting it here would suggest the check
    # depends on an authorization decision it does not make.
    # IAM has no API that reports a policy has become effective, so there is nothing to poll here.
    # Correctness comes entirely from the bounded retry at first USE (the CreateFunction loop
    # below), which already tolerates the propagation delay — an unconditional sleep here would add
    # nothing but fixed wall clock to every run.
    return arn


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


def _make_zip() -> bytes:
    """The handler plus a VENDORED copy of kafka-python out of this host's site-packages.

    kafka-python is pure Python and ~0.6 MB zipped, so the whole client travels in the deployment
    package. That is what makes the in-VPC probe a real client rather than a hand-framed subset.
    There is no availability branch: a missing kafka-python is an ImportError at module scope,
    which is a FAIL, since the runner is guaranteed to carry it.
    """
    root = os.path.dirname(kafka.__file__)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER_SRC)
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                if f.endswith((".pyc", ".pyo")):
                    continue
                p = os.path.join(base, f)
                zf.write(p, os.path.join("kafka", os.path.relpath(p, root)))
    return buf.getvalue()


def _lambda_client(ctx):
    """A Lambda client whose READ timeout outlives the function's own timeout. botocore's default
    read timeout is 60 s, so a synchronous Invoke of a function that legitimately runs for minutes
    times out client-side and botocore RETRIES it. Retries are disabled for the same reason."""
    return ctx.client("lambda", config=BotoConfig(
        read_timeout=_FN_TIMEOUT_S + 60, connect_timeout=20, retries={"max_attempts": 0}))


_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions", "CreateNetworkInterface")


def _deploy(ctx, lam, net: dict, role_arn: str) -> str:
    """CreateFunction with VpcConfig, retried through IAM propagation, then wait Active. The retry
    is what makes this correct rather than flaky: a role created seconds ago is not yet visible to
    Lambda, and CreateFunction rejects it synchronously naming either the trust relationship or the
    missing EC2 action."""
    name = ctx.unique_name("sim2real-behav-kdp-fn-")
    kwargs = dict(FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                  Code={"ZipFile": _make_zip()}, MemorySize=512, Timeout=_FN_TIMEOUT_S,
                  VpcConfig={"SubnetIds": net["subnet_ids"], "SecurityGroupIds": [net["sg_id"]]},
                  Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS})
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
                    f"CreateFunction with VpcConfig={kwargs['VpcConfig']!r} was rejected: "
                    f"{_code_of(exc)}: {msg}") from exc
            time.sleep(5)
    print(f"[ledger] created Lambda executor {name}")
    ctx.on_cleanup(lambda: _delete_fn(ctx, lam, name))
    last = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State") in ("Active", "Failed"),
                 timeout_s=300, interval_s=5)
    if last is None:
        raise AssertionError(
            f"the in-VPC executor {name} did not reach State=Active within the bounded wait (a "
            f"first Hyperplane ENI in a fresh subnet/security-group pair is the slow part)")
    if last["State"] != "Active":
        raise _no_executor(f"{name} entered State={last['State']!r}: {last.get('StateReason')!r}")
    return name


def _delete_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group its first invocation created. Returns immediately —
    Lambda releases the Hyperplane ENI asynchronously and nothing here waits for it, which is
    exactly why the network is retained rather than torn down. Both deletes are attempted even if
    one fails; only the resource's own not-found code means it is already gone."""
    errors = []
    for fn in (lambda: lam.delete_function(FunctionName=name),
               lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
        try:
            fn()
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFound":
                errors.append(exc)
    if errors:
        raise errors[0]


#: Ops whose effect is IDEMPOTENT, so re-invoking one after a transport failure cannot change what
#: the check goes on to assert. `admin` is here because a create that already landed comes back as
#: TopicAlreadyExistsError, which the handler absorbs.
_REPLAYABLE_OPS = frozenset({"selftest", "tcp_ready", "kafka_ready", "api_versions", "admin"})

#: Invoke-level failures that say nothing about the function: Lambda declining the call before it
#: runs. Retries are disabled on the client (see _lambda_client), so they are handled here.
_INVOKE_TRANSIENT = ("ServiceException", "TooManyRequestsException", "ThrottlingException",
                     "EC2ThrottledException", "ResourceNotReadyException")


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result. A FunctionError or a non-200
    means the RUNTIME failed, not that the handler reported a failure — the handler never raises —
    so anything arriving there is the executor being unusable rather than a verdict about Kafka."""
    op = payload.get("op")
    deadline = time.monotonic() + 300
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                              Payload=json.dumps(payload).encode())
            break
        except (ConnectionClosedError, EndpointConnectionError) as exc:
            # The client's retries are off, so a pooled connection the endpoint closed while the
            # cluster was building surfaces here; only a replayable op may be sent again.
            if op not in _REPLAYABLE_OPS or time.monotonic() >= deadline:
                raise _no_executor(f"Invoke({op!r}) failed: {type(exc).__name__}: {exc}") from exc
            time.sleep(2)
        except ClientError as exc:
            retryable = (op in _REPLAYABLE_OPS
                         and _code_of(exc).rstrip("Exception") in
                         tuple(c.rstrip("Exception") for c in _INVOKE_TRANSIENT))
            if not retryable or time.monotonic() >= deadline:
                raise _no_executor(f"Invoke({op!r}) failed: {_code_of(exc)}: {_msg_of(exc)}") from exc
            time.sleep(2)
    body = resp["Payload"].read().decode()
    if resp.get("FunctionError"):
        raise _no_executor(
            f"Invoke({op!r}) returned FunctionError={resp['FunctionError']!r}: {body[:900]}")
    assert resp.get("StatusCode") == 200, (
        f"Invoke({op!r}) returned StatusCode={resp.get('StatusCode')!r}, not 200: {body[:300]}")
    try:
        out = json.loads(body)
    except ValueError as exc:
        raise _no_executor(f"Invoke({op!r}) returned non-JSON: {body[:900]}") from exc
    assert isinstance(out, dict), f"Invoke({op!r}) returned {out!r}, not an object"
    return out


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict) -> str:
    """Run the selftest and decide, BEFORE anything billable exists, whether the instrument is
    actually inside the VPC. Two claims established separately:

    1. THE CODE RAN. The handler returns sha256("<nonce>|<src_ip>|<rcode>") over a nonce minted
       here, and because the digest also covers the two network fields, a target that runs the
       code and then rewrites the response invalidates its own proof.
    2. IT RAN INSIDE OUR VPC. Either the source address a packet toward an in-VPC address would
       carry falls inside the randomized VPC CIDR, or the VPC's Route 53 Resolver at CIDR-base+2
       replied — an address answerable ONLY from inside that VPC.

    Once this returns, a subsequent failure to reach the brokers is unambiguously the brokers'.
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


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _log_group(ctx, logs, suffix: str) -> str:
    """A CloudWatch log group under /aws/vendedlogs/, created in-check and idempotently.

    The /aws/vendedlogs/ prefix is not cosmetic. MSK adds each wired log group's ARN to the shared
    AWSLogDeliveryWrite20150319 resource policy, which has a 5120-character quota; once it is full,
    CloudWatch Logs falls back to a wildcard entry for /aws/vendedlogs/* instead. A group outside
    that prefix in a busy shared account therefore fails cluster creation with
    InvalidInput.LengthOfCloudWatchResourcePolicyLimitExceeded — a failure that looks like a fidelity
    finding and is not one. Source: AWS re:Post, "How do I resolve the 'did not stabilize' error ...
    AWS::MSK::Cluster", and the CloudWatch Logs guide's "Logging that requires additional
    permissions".
    """
    name = f"/aws/vendedlogs/{ctx.unique_name('sim2real-behav-kmsklog-')}-{suffix}"
    try:
        logs.create_log_group(logGroupName=name, tags={t["Key"].replace(":", "-"): t["Value"]
                                                       for t in _MANAGED_TAGS})
    except ClientError as exc:
        # Create-or-adopt: a retried run in the same account must not fail on its own leftover.
        if _code_of(exc) != "ResourceAlreadyExists":
            raise
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    print(f"[ledger] created log group {name}")
    return name


def _delete_log_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if _code_of(exc) not in ("ResourceNotFound", "NotFound"):
            raise


def _bucket(ctx, s3) -> str:
    """An S3 bucket for broker logs, created in-check.

    No bucket policy is attached here, deliberately: MSK creates one itself when the S3 destination
    is configured (the caller needs only s3:PutBucketPolicy, per the MSK logging guide's "Required
    permissions"). Writing our own would both be redundant and make the check pass on a target that
    never asked for delivery permission.
    """
    name = ctx.unique_name("sim2real-behav-kmsklog-")[:63].lower()
    kwargs = {"Bucket": name}
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _MANAGED_TAGS})
    print(f"[ledger] created S3 bucket {name}")
    return name


def _delete_bucket(s3, name: str) -> None:
    """Empty then delete. Paginated: MSK writes one object per broker per rotation and an
    unpaginated list would leave the tail behind, which fails the delete and leaks the bucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if _code_of(exc) not in ("NoSuchBucket", "NotFound"):
            raise


def _first_event_latency(logs, group: str, *, timeout_s: float) -> tuple[float, list]:
    """Poll the WIRED log group until it holds at least one event, and return (latency, events).

    RAISES on timeout: broker logs that never arrive are the defect this check exists to detect,
    not a reason to proceed with a weaker assertion.
    """
    t0 = time.monotonic()
    found = _poll(lambda: _events(logs, group),
                  lambda evs: len(evs) > 0,
                  timeout_s=timeout_s, interval_s=15)
    if found is None:
        streams = _paginate(logs, "describe_log_streams", "logStreams", logGroupName=group)
        raise AssertionError(
            f"{DELIVERY_MARKER}: the log group {group} wired into LoggingInfo.BrokerLogs."
            f"CloudWatchLogs received no log event within {timeout_s}s of the cluster reaching "
            f"ACTIVE and being produced to. It holds {len(streams)!r} log streams "
            f"({[s.get('logStreamName') for s in streams][:5]!r}). MSK documents INFO-level broker "
            f"logs as delivered to the configured destination; a cluster that accepts the "
            f"configuration and delivers nothing is the gap")
    return time.monotonic() - t0, found


def _events(logs, group: str) -> list:
    """Every event in the group, through FilterLogEvents — a read at the CONSUMER, issued through a
    different operation than anything that configured delivery."""
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(logGroupName=group):
            out.extend(page.get("events", []))
    except ClientError as exc:
        if _code_of(exc) in ("ResourceNotFound", "NotFound"):
            return []
        raise
    return out


def _s3_objects(s3, bucket: str, prefix: str) -> list:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(page.get("Contents", []))
    return out

# ---- the cluster -----------------------------------------------------------------------------


def _create_provisioned_cluster(ctx, msk, net: dict, wired_group: str, bucket: str) -> str:
    """A PROVISIONED MSK cluster whose LoggingInfo names ONE of the two log groups this check created,
    plus the S3 bucket, and whose Firehose destination is explicitly DISABLED.

    Two destinations in one cluster rather than two clusters, because a second provisioned cluster
    would double the most expensive part of the run to grade a delivery path that is independent of
    the first. The Firehose leg is submitted as Enabled=false so the structure carries all three
    destinations and a target that opens whatever it is handed has something to get wrong.

    Provisioned rather than Serverless because LoggingInfo does not exist on MSK Serverless, at the
    cost of 20-40 minutes to ACTIVE. PLAINTEXT and unauthenticated on the Kafka listener so a
    handshake failure is never reported as a log-delivery finding.
    """
    subnets = sorted(net["subnet_ids"])[:_BROKERS]
    assert len(subnets) == _BROKERS, (
        f"the executor network offers subnets {net['subnet_ids']!r}; this check needs exactly "
        f"{_BROKERS} so every broker can be probed independently")
    name = ctx.unique_name("sim2real-behav-kmon-msk-")[:64]
    try:
        created = msk.create_cluster(
            ClusterName=name,
            KafkaVersion=_KAFKA_VERSION,
            NumberOfBrokerNodes=len(subnets),
            BrokerNodeGroupInfo={"InstanceType": _BROKER_TYPE, "ClientSubnets": subnets,
                                 "SecurityGroups": [net["sg_id"]]},
            LoggingInfo={"BrokerLogs": {
                "CloudWatchLogs": {"Enabled": True, "LogGroup": wired_group},
                "S3": {"Enabled": True, "Bucket": bucket, "Prefix": _S3_PREFIX},
                "Firehose": {"Enabled": False}}},
            EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "PLAINTEXT",
                                                    "InCluster": True}},
            ClientAuthentication={"Unauthenticated": {"Enabled": True}},
            Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS})
    except ClientError as exc:
        if _code_of(exc) not in _MSK_NO_CAPACITY:
            raise
        raise AssertionError(
            f"MSK cannot currently place {len(subnets)}x {_BROKER_TYPE} in {subnets!r}: "
            f"{_msg_of(exc)}") from exc
    arn = created["ClusterArn"]
    # Registered IMMEDIATELY, before the ACTIVE poll: two brokers are the only billable thing this
    # check creates and a poll that times out must not strand them.
    ctx.on_cleanup(lambda: _delete_cluster(msk, arn))
    print(f"[ledger] CREATED PROVISIONED MSK CLUSTER {arn} logs->{wired_group} "
          f"s3->{bucket}/{_S3_PREFIX} firehose=off")
    assert created.get("State") in ("CREATING", "ACTIVE"), (
        f"create_cluster reported State={created.get('State')!r} for {name!r}, expected 'CREATING' "
        f"or 'ACTIVE'")
    return arn


def _broker_hosts(bootstrap: str) -> list[str]:
    """Every broker hostname the PLAINTEXT bootstrap string advertises. The exporters are per-broker,
    so probing only the first would let a target that runs one exporter and none on the others pass."""
    hosts = sorted({e.rpartition(":")[0] for e in bootstrap.split(",") if e.strip()})
    assert hosts, f"no broker hosts could be parsed out of {bootstrap!r}"
    return hosts


def _await_active(ctx, msk, arn: str, *, timeout_s: float, why: str) -> dict:
    """Poll to ACTIVE, RAISING on timeout. Never returns the last value: a caller that treated a
    timeout as an observation would assert against a cluster that is still changing."""
    desc = _poll(lambda: msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"],
                 lambda d: d["State"] in ("ACTIVE", "FAILED"),
                 timeout_s=timeout_s, interval_s=30)
    if desc is None:
        raise AssertionError(
            f"{arn} did not reach a terminal state within {timeout_s}s while {why}; last state was "
            f"{msk.describe_cluster_v2(ClusterArn=arn)['ClusterInfo']['State']!r}")
    assert desc["State"] == "ACTIVE", (
        f"cluster {arn} is {desc['State']!r} after {why}, expected 'ACTIVE': "
        f"{desc.get('StateInfo')!r}")
    return desc


def _delete_cluster(msk, arn: str) -> None:
    """DeleteCluster, then POLL that the deletion actually progressed and raise if it did not —
    the most expensive resource in this suite, so a refusal or a stall must not pass as clean."""
    try:
        msk.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if _code_of(exc) not in ("NotFound", "ResourceNotFound"):
            raise
        return

    def _state():
        try:
            return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if _code_of(exc) in ("NotFound", "ResourceNotFound"):
                return "GONE"
            raise

    last = _poll(_state, lambda s: s in ("DELETING", "GONE"), timeout_s=180, interval_s=10)
    if last is None:
        raise AssertionError(
            f"DeleteCluster for {arn} was accepted but the cluster never progressed past "
            f"{_state()!r} within 180s; it is stranded, not deleted")


def _bootstrap(msk, arn: str) -> str:
    """The PLAINTEXT bootstrap string, polled: GetBootstrapBrokers can answer before the endpoint is
    published even on a cluster that already reports ACTIVE."""
    resp = _poll(lambda: msk.get_bootstrap_brokers(ClusterArn=arn),
                 lambda r: bool(r.get("BootstrapBrokerString")),
                 timeout_s=300, interval_s=15)
    if resp is None:
        offered = sorted(k for k in msk.get_bootstrap_brokers(ClusterArn=arn)
                         if k.startswith("Bootstrap"))
        raise _dp_fail(
            f"{arn} is ACTIVE but never published a BootstrapBrokerString; the keys it offered "
            f"were {offered!r}. Without an address there is no data plane and the Configuration "
            f"cannot be observed taking effect")
    return resp["BootstrapBrokerString"]


def _await_data_plane(ctx, lam, fn: str, bootstrap: str) -> dict:
    """Poll until the cluster's bootstrap endpoint ACCEPTS TCP and then SERVES Kafka.

    This exists because of a measured gap no AWS API reports: an MSK Serverless cluster reaches
    State=ACTIVE about 140 s after CreateClusterV2 and GetBootstrapBrokers answers immediately, but
    its PLAINTEXT listener does not accept a connection on 9092 for some time after that. Too short a wait reports a false fidelity failure against a cluster that was merely
    still coming up. This is a poll on an OBSERVABLE CONDITION — a completed TCP handshake, then a
    served metadata request — never a sleep sized to make it pass. An endpoint that never accepts
    is a FAIL: a cluster the control plane advertises and nothing will talk to is precisely the
    defect this suite exists to catch.
    """
    deadline = time.monotonic() + 900
    t0 = time.monotonic()
    tcp = {}
    while time.monotonic() < deadline:
        tcp = _invoke(ctx, lam, fn, {"op": "tcp_ready", "bootstrap": bootstrap, "timeout_s": 10})
        if tcp.get("connected"):
            print(f"[check] endpoint accepted TCP at t+{time.monotonic() - t0:.0f}s after ACTIVE: "
                  f"{tcp.get('target')!r} peer={tcp.get('peer')!r}")
            break
        time.sleep(2)
    else:
        raise _dp_fail(
            f"{bootstrap} was advertised by an ACTIVE cluster but never accepted a TCP connection "
            f"in {time.monotonic() - t0:.0f}s from inside its own VPC. The executor was already "
            f"proven in-VPC and the security group admits tcp/{_KAFKA_PORT} between members of the "
            f"one group both the Lambda ENI and the brokers belong to. Last: {tcp!r}")
    last = {}
    while time.monotonic() < deadline:
        last = _invoke(ctx, lam, fn, {"op": "kafka_ready", "bootstrap": bootstrap,
                                      "security_protocol": "PLAINTEXT"})
        if last.get("serving"):
            print(f"[check] broker served the Kafka admin protocol at "
                  f"t+{time.monotonic() - t0:.0f}s after ACTIVE")
            return dict(tcp, **{"kafka_ready": last})
        time.sleep(2)
    raise _dp_fail(
        f"{bootstrap} accepted TCP but never served a Kafka metadata request within "
        f"{time.monotonic() - t0:.0f}s of the cluster reporting ACTIVE, from inside its own VPC. A "
        f"socket that accepts and a broker that answers are different things and this is the "
        f"second. Last attempt: {last!r}")


def _bring_up(ctx):
    """Build the in-VPC executor, PROVE it is inside the VPC, then create the cluster.

    The order is load-bearing: everything cheap and fully decidable happens BEFORE the create, so a
    broken instrument never bills a cluster, and once the executor is proven in-VPC a subsequent
    failure to reach the brokers is unambiguously the brokers'.
    """
    ec2, iam, msk = ctx.client("ec2"), ctx.client("iam"), ctx.client("kafka")
    lam = _lambda_client(ctx)
    net = _network(ctx, ec2)
    role_arn = _exec_role(ctx, iam)
    fn = _deploy(ctx, lam, net, role_arn)
    print(f"[check] executor proven in-VPC: {_prove_executor_in_vpc(ctx, lam, fn, net)}")

    logs, s3 = ctx.client("logs"), ctx.client("s3")
    # TWO log groups, only one of which is wired. Both are created before the cluster so they exist
    # for exactly the same length of time and differ in nothing but LoggingInfo membership.
    wired = _log_group(ctx, logs, "wired")
    unwired = _log_group(ctx, logs, "unwired")
    bucket = _bucket(ctx, s3)

    cluster_arn = _create_provisioned_cluster(ctx, msk, net, wired, bucket)
    # MSK provisioning is genuinely slow; the same budget holds on every target, and a target
    # that provisions sooner ends the poll sooner.
    desc = _await_active(ctx, msk, cluster_arn, timeout_s=2700, why="reaching ACTIVE after create")
    # The control plane's own claim about the three destinations, so a later delivery disagreement is
    # unambiguously the SERVICE's and not a cluster that silently dropped the LoggingInfo struct.
    bl = (((desc.get("Provisioned") or {}).get("LoggingInfo") or {}).get("BrokerLogs") or {})
    assert (bl.get("CloudWatchLogs") or {}).get("LogGroup") == wired, (
        f"DescribeClusterV2 reports BrokerLogs={bl!r}; CloudWatchLogs.LogGroup must be the "
        f"{wired!r} passed to CreateCluster")
    assert (bl.get("CloudWatchLogs") or {}).get("Enabled") is True, (
        f"DescribeClusterV2 reports BrokerLogs.CloudWatchLogs={bl.get('CloudWatchLogs')!r}; "
        f"Enabled must be True")
    assert (bl.get("S3") or {}).get("Bucket") == bucket, (
        f"DescribeClusterV2 reports BrokerLogs.S3={bl.get('S3')!r}; Bucket must be the {bucket!r} "
        f"passed to CreateCluster")
    assert (bl.get("S3") or {}).get("Prefix") == _S3_PREFIX, (
        f"DescribeClusterV2 reports BrokerLogs.S3.Prefix={(bl.get('S3') or {}).get('Prefix')!r}, "
        f"not the {_S3_PREFIX!r} passed to CreateCluster")
    assert (bl.get("Firehose") or {}).get("Enabled") is False, (
        f"DescribeClusterV2 reports BrokerLogs.Firehose={bl.get('Firehose')!r}; Enabled must be "
        f"False, which is what CreateCluster asked for")

    bootstrap = _bootstrap(msk, cluster_arn)
    for endpoint in bootstrap.split(","):
        host, _, port = endpoint.rpartition(":")
        assert int(port) > 0, (
            f"every PLAINTEXT bootstrap endpoint must carry a port, got {port!r} "
            f"(from {bootstrap!r})")
        assert re.fullmatch(r"[A-Za-z0-9.-]+", host), (
            f"bootstrap host {host!r} is not a well-formed broker host name "
            f"(from {bootstrap!r})")
    _await_data_plane(ctx, lam, fn, bootstrap)
    # What answered speaks Apache Kafka, not merely TCP: ApiVersions returns error_code 0 and
    # advertises the api keys a real broker does. Hand-framed, so no client library is between the
    # broker's bytes and this assertion.
    probe = _invoke(ctx, lam, fn, {"op": "api_versions", "bootstrap": bootstrap,
                                   "api_versions_api_key": _API_VERSIONS_API_KEY,
                                   "timeout_s": 20})
    if not probe.get("ok"):
        raise _dp_fail(
            f"the PLAINTEXT listener {probe.get('target')!r} accepted TCP but did not answer a "
            f"hand-framed ApiVersions request (stage {probe.get('stage')!r}): "
            f"{probe.get('error')!r}")
    assert probe.get("error_code") == 0, (
        f"ApiVersions on {probe.get('target')!r} returned error_code {probe.get('error_code')!r}, "
        f"expected 0")
    # CreateTopics (19), Metadata (3), DescribeConfigs (32) and Produce (0) are the api keys the
    # rest of this check depends on. Asserting their PRESENCE (not a version range) keeps this a
    # capability check rather than a pinned protocol version.
    for key in (0, 3, 19, 32):
        assert key in (probe.get("api_keys") or []), (
            f"the broker's ApiVersions response advertises {probe.get('n_api_keys')!r} api keys "
            f"and does not include key {key}, which the rest of this check needs: "
            f"{probe.get('api_keys')!r}")
    return lam, fn, msk, cluster_arn, bootstrap, wired, unwired, bucket


def _looks_like_broker_log(text: str) -> bool:
    """Does `text` contain an Apache Kafka broker log line?

    Two independent signals must BOTH appear: a log4j level token and a Kafka logger name. Either
    alone is far too weak — "INFO" appears in almost any text, and so does the word kafka in a bucket
    this check named.
    """
    has_level = any(f" {lvl} " in text or f"[{lvl}]" in text
                    for lvl in ("INFO", "WARN", "ERROR"))
    has_logger = "org.apache.kafka" in text or "kafka." in text
    return has_level and has_logger


def _decompress(raw: bytes) -> tuple[str, str]:
    """(how, text). Vended logs are normally gzip; the raw fallback exists so a doc drift is RECORDED
    rather than crashing the decode, and `how` is reported so the run's output says which happened.
    It never changes what is asserted about the content."""
    try:
        return "gzip", gzip.decompress(raw).decode("utf-8", "replace")
    except (OSError, EOFError, gzip.BadGzipFile):
        return "raw", raw.decode("utf-8", "replace")


# concern:eventing and NOT concern:metrics. Broker log DELIVERY is routing and delivery semantics;
# `metrics` in schemas/tags.json is "a metric/log signal reaches an alarm or metric filter and
# drives an action", and nothing here drives an action. Claiming metrics would overstate what is
# graded — a heuristic tag is worse than an absent one.
@tags("axis:happy-path", "cap:c1", "concern:eventing", "concern:negative-classes", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """Real broker log lines reach exactly the destinations named in LoggingInfo.BrokerLogs — the
    wired CloudWatch log group and the configured S3 prefix — while a second log group left out
    of LoggingInfo stays empty over a window sized from the measured delivery latency.

    Reference: https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html
    """
    lam, fn, _msk, _arn, bootstrap, wired, unwired, bucket = _bring_up(ctx)
    logs, s3 = ctx.client("logs"), ctx.client("s3")

    # Give the brokers something to log about. A cluster that has never been connected to still emits
    # controller and log-manager lines, but driving real traffic makes the evidence unambiguous and
    # also proves the cluster is genuinely serving while its logs are being graded.
    topic = ctx.unique_name("sim2real-behav-kmsklog-topic-")
    base = {"bootstrap": bootstrap, "security_protocol": "PLAINTEXT"}
    made = _invoke(ctx, lam, fn, dict(base, op="admin", topic=topic,
                                      partitions=_TOPIC_PARTITIONS, replication=_BROKERS))
    if not made.get("ok"):
        raise _dp_fail(
            f"could not create {topic!r} on {bootstrap!r} (stage {made.get('stage')!r}): "
            f"{made.get('error')!r}; without traffic the broker-log evidence would be ambiguous")
    produced = _invoke(ctx, lam, fn, dict(base, op="produce", topic=topic,
                                          values=[_b64(b"sim2real-kmsklog-%d" % i)
                                                  for i in range(_RECORDS)]))
    if not produced.get("ok"):
        raise _dp_fail(
            f"producing {_RECORDS} records to {topic!r} failed: errors={produced.get('errors')!r} "
            f"flush={produced.get('flush_error')!r}")

    # ---- the wired CloudWatch group --------------------------------------------------------------
    latency, events = _first_event_latency(logs, wired, timeout_s=900)
    print(f"[check] first broker log event reached {wired} after {latency:.0f}s "
          f"({len(events)!r} events on arrival)")
    streams = _paginate(logs, "describe_log_streams", "logStreams", logGroupName=wired)
    assert streams, (
        f"{DELIVERY_MARKER}: {wired} reports {len(events)!r} events through FilterLogEvents but "
        f"DescribeLogStreams lists no streams at all, which is self-contradictory")
    messages = "\n".join(e.get("message") or "" for e in events)
    assert _looks_like_broker_log(messages), (
        f"{DELIVERY_MARKER}: {wired} received {len(events)!r} events in "
        f"{[s.get('logStreamName') for s in streams][:3]!r} but none is recognisable as an Apache "
        f"Kafka broker log line (a log4j level token AND a kafka logger name). First 300 chars: "
        f"{messages[:300]!r}")

    # ---- the S3 destination, an entirely separate delivery path -------------------------------
    # MSK's S3 destination writes a Size=0 object at the prefix ROOT
    # (<prefix>/AWSLogs/<account>/) within seconds of the cluster reaching ACTIVE, well before any
    # broker log content lands, so a bare "an object exists" check would pass while the object
    # carries zero bytes. So the poll below requires a NON-EMPTY object,
    # not merely a listed one; H3 still holds and the key layout beyond the configured prefix is
    # not asserted.
    objects = _poll(lambda: [o for o in _s3_objects(s3, bucket, _S3_PREFIX) if o.get("Size")],
                    lambda objs: len(objs) > 0,
                    timeout_s=900, interval_s=30)
    if objects is None:
        everything = _s3_objects(s3, bucket, "")
        raise AssertionError(
            f"{DELIVERY_MARKER}: no NON-EMPTY object appeared under s3://{bucket}/{_S3_PREFIX} "
            f"within the bounded wait, although CloudWatch delivery to {wired} was already "
            f"flowing ({len(events)!r} events after {latency:.0f}s). The bucket holds "
            f"{len(everything)!r} objects in total "
            f"({[(o['Key'], o.get('Size')) for o in everything][:5]!r}) — a Size=0 object at the "
            f"prefix root is MSK's own delivery marker, not broker log content; if every object "
            f"here is that marker, S3 delivery itself is the gap")
    body = s3.get_object(Bucket=bucket, Key=objects[0]["Key"])["Body"].read()
    how, text = _decompress(body)
    print(f"[check] s3://{bucket}/{objects[0]['Key']} is {len(body)!r} bytes, decoded as {how}, "
          f"{len(objects)!r} objects under {_S3_PREFIX!r}")
    assert _looks_like_broker_log(text), (
        f"{DELIVERY_MARKER}: s3://{bucket}/{objects[0]['Key']} ({len(body)!r} bytes, decoded as "
        f"{how}) does not contain a recognisable Apache Kafka broker log line. First 300 chars of "
        f"the decoded body: {text[:300]!r}")

    # ---- the negative: the UNWIRED group must stay empty --------------------------------------
    # Held for at least `window` AND until a broker log event stamped after `start_ms` reaches the
    # wired group (the positive control: an event misrouted at the same time would show by then).
    window = max(_ABSENCE_MULTIPLE * latency, _ABSENCE_FLOOR_S)
    start_ms = int(time.time() * 1000)
    baseline = len(_events(logs, wired))
    print(f"[check] holding the absence on {unwired} for at least {window:.0f}s "
          f"({_ABSENCE_MULTIPLE}x the measured {latency:.0f}s, floored at {_ABSENCE_FLOOR_S:.0f}s)")
    start = time.monotonic()
    bound = max(window, _CONTROL_TIMEOUT_S)
    left = ctx.time_left()
    if left is not None:
        bound = min(bound, left)
    deadline = start + bound
    while True:
        fresh = [e for e in _events(logs, wired) if (e.get("timestamp") or 0) > start_ms]
        # Two independent observables, not one: an events read AND a streams read. A target that
        # answers an empty FilterLogEvents for everything is caught by the wired group's own
        # non-empty answer above, and a group with streams but no events is a different finding.
        stray = _events(logs, unwired)
        assert not stray, (
            f"the log group {unwired} was created in this run and deliberately left OUT of "
            f"LoggingInfo.BrokerLogs, yet it received {len(stray)!r} events: "
            f"{[(e.get('logStreamName'), (e.get('message') or '')[:80]) for e in stray][:3]!r}. "
            f"Broker logs are going somewhere they were not configured to go")
        stray_streams = _paginate(logs, "describe_log_streams", "logStreams", logGroupName=unwired)
        assert not stray_streams, (
            f"the unwired log group {unwired} has log streams "
            f"{[s.get('logStreamName') for s in stray_streams][:5]!r}; it was never named in "
            f"LoggingInfo and nothing should have created a stream in it")
        if fresh and time.monotonic() >= start + window:
            break
        if time.monotonic() >= deadline:
            if fresh:
                raise AssertionError(
                    f"the absence on {unwired} could not be held for the {window:.0f}s window "
                    f"within the {bound:.0f}s left to this check")
            raise AssertionError(
                f"{DELIVERY_MARKER}: no broker log event stamped after the absence observation "
                f"began reached the wired group {wired} within {bound:.0f}s, so the "
                f"negative leg on {unwired} has no positive control behind it")
        time.sleep(2)
    # And delivery was LIVE throughout, so the absence above is a fact about the unwired group rather
    # than about a delivery path that stopped.
    final = len(_events(logs, wired))
    assert final > baseline, (
        f"the wired group {wired} held {baseline!r} events at the start of the absence "
        f"observation and {final!r} at the end. Delivery was not demonstrably live while "
        f"{unwired} was being observed empty, so the negative leg has no positive control behind it")
    print(f"[check] {unwired} stayed empty for {time.monotonic() - start:.0f}s while {wired} grew "
          f"{baseline!r} -> {final!r} events")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
