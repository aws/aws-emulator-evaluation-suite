"""cache-cluster-resp-protocol-round-trip-over-socket."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-cluster-resp-protocol-round-trip-over-socket"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

_NODE_TYPE = "cache.t3.micro"
_REDIS_PORT = 6379

# Tags for the resources this check creates. `sim2real:managed=true` is what an account cleanup
# discovers through the Resource Groups Tagging API, and `sim2real` names
# the scenario so a leftover can be attributed to this file rather than to "some elasticache run".
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

# Marks a failure as a native data-plane failure. The message interpolates the socket error the
# probe caught (`ConnectionRefusedError('Connection refused')`), so without the marker the one verdict
# this check exists to produce — the advertised endpoint speaks nothing — would read as a
# client-side environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


# The RESP codec (in the in-VPC probe
# below) is written from the RESP2 wire format itself: there is no Redis client in the allowed
# dependency set. Hand-framing the protocol is what makes this check hard-fail instead of skip.
def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None


def _poll(probe, predicate, timeout_s=1500, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _describe_cluster(ec, cluster_id, **extra):
    return _describe_one(
        ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, **extra
    )


def _delete_cluster_and_wait(ec, cluster_id, timeout_s=1500, interval_s=15):
    """Delete a cache cluster and poll it to actual disappearance.

    Registered at creation time. A cluster still `creating` refuses deletion with
    InvalidCacheClusterState, so this retries rather than leaking a billable node.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            break
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    _poll(lambda: _describe_cluster(ec, cluster_id), lambda c: c is None,
          timeout_s=timeout_s, interval_s=interval_s)


def _delete_security_group_when_free(ec2, group_id, timeout_s=900, interval_s=15):
    """Delete a security group, retrying while cache-node ENIs still reference it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=group_id)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code") or ""
            if code in ("InvalidGroup.NotFound", "InvalidGroupId.NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _probe_scoped_security_group(ec2, ctx, net, probe, port):
    """A security group in the run's network allowing `port` from the in-VPC probe's group ONLY.

    An ElastiCache node is a private VPC resource and a world-open ingress rule on a cache port
    is exactly the misconfiguration this check should not be modelling.
    """
    group_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-ecsgrp-"),
        Description="sim2real elasticache RESP data-plane check (probe-scoped ingress)",
        VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _RESOURCE_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, group_id))
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "UserIdGroupPairs": [{"GroupId": probe["sg"], "Description": "in-VPC probe only"}],
        }],
    )
    return group_id


def _subnet_group(ec, ctx, net):
    name = ctx.unique_name("sim2real-behav-ecsng-resp-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real elasticache RESP data-plane check",
        SubnetIds=net.subnet_ids[:2],
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """The endpoint a Redis cache cluster advertises speaks the Redis wire protocol: a raw RESP2 exchange
    over a TCP socket round-trips a value and keeps the framings apart -- a missing key's `$-1` from an
    empty string's `$0`, and TTL's `-1` (no expiry) from `-2` (no key).
    """
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")

    # Registered before the cluster, so LIFO teardown drops the cluster first.
    net = ctx.network()
    probe = _probe_open(ctx, net)
    group_id = _probe_scoped_security_group(ec2, ctx, net, probe, _REDIS_PORT)
    subnet_group = _subnet_group(ec, ctx, net)

    cluster_id = ctx.unique_name("sim2real-behav-ecc-resp-")
    created = ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType=_NODE_TYPE,
        NumCacheNodes=1,
        Port=_REDIS_PORT,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[group_id],
        TransitEncryptionEnabled=False,
        Tags=_RESOURCE_TAGS,
    )["CacheCluster"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ec, cluster_id))
    assert created["CacheClusterStatus"] == "creating", created["CacheClusterStatus"]

    _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and c.get("CacheClusterStatus") == "available",
        timeout_s=1500,
    )

    # ---- the advertised endpoint must be a real, well-formed address ----------------
    detailed = _poll(
        lambda: _describe_cluster(ec, cluster_id, ShowCacheNodeInfo=True),
        lambda c: bool((c or {}).get("CacheNodes")),
        timeout_s=300,
        interval_s=10,
    )
    nodes = detailed["CacheNodes"]
    assert len(nodes) == 1, nodes
    endpoint = nodes[0].get("Endpoint") or {}
    host = endpoint.get("Address")
    port = endpoint.get("Port")
    assert host, (
        f"an available Redis cache node advertised no Endpoint.Address: {nodes[0]}; without an "
        f"address there is no data plane to reach"
    )
    key = "sim2real:resp:" + str(int(time.time()))
    empty_key = key + ":empty"
    missing_key = key + ":never-written"
    value = "sim2real-value"
    plan = [
        ["PING"],
        ["SET", key, value], ["GET", key],
        ["GET", missing_key], ["SET", empty_key, ""], ["GET", empty_key],
        ["TTL", key], ["TTL", missing_key], ["EXPIRE", key, "100"], ["TTL", key], ["EXPIRE", missing_key, "100"],
        ["INCR", key], ["GET", key],
        ["SIM2REALNOTACOMMAND", "arg"],
        ["DEL", key], ["GET", key], ["DEL", key],
    ]
    (session,) = _probe_call(ctx, probe, host, port, [{"tls": False, "commands": plan}])
    _probe_release(ctx, probe)
    r = session["replies"]
    if not r and (session["error"] or "").startswith("connect:"):
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the cache endpoint {host}:{port} advertised in DescribeCacheClusters "
            f"accepts no TCP connection from inside its own VPC ({session['error']}); an endpoint "
            f"that cannot be connected to is not a data plane"
        )
    assert session["error"] is None and len(r) == len(plan), (
        f"the endpoint framed {len(r)} of {len(plan)} replies before {session['error']!r}; a short "
        f"list means it answered with something that is not a RESP2 reply. Replies: {r!r}"
    )
    (pong, set_reply, get_reply, missing_reply, set_empty, empty_reply, ttl_none, ttl_missing,
     expire_reply, ttl, expire_missing, incr_reply, get_after_incr, unknown_reply,
     del_reply, get_after_del, del_again) = r

    # ---- liveness: the endpoint speaks RESP, not just TCP -----------------------
    assert pong == "+PONG", (
        f"PING must return the simple string +PONG, got {pong!r}; the endpoint accepts TCP "
        f"but is not speaking the Redis protocol"
    )

    # ---- SET / GET round-trip, asserted on the bulk-string framing --------------
    assert set_reply == "+OK", f"SET must return +OK, got {set_reply!r}"
    expected_get = "$" + value
    assert get_reply == expected_get, (
        f"GET must return the value as a length-prefixed bulk string {expected_get!r}, got "
        f"{get_reply!r}; the data plane did not durably store the value"
    )

    # ---- the framing that matters: absent key vs present-but-empty key ----------
    assert missing_reply is None, (
        f"GET on a key that was never written must return the NULL bulk string $-1, got "
        f"{missing_reply!r}"
    )
    assert set_empty == "+OK"
    assert empty_reply == "$", (
        f"GET on a key holding the empty string must return $0 with an empty payload, got "
        f"{empty_reply!r}"
    )
    assert empty_reply != missing_reply, (
        "an absent key and a key holding the empty string returned the SAME reply "
        f"({empty_reply!r}); conflating them is the single most consequential Redis "
        "emulation bug, because every client's exists/None logic depends on the difference"
    )

    # ---- expiry: integer replies, and TTL's three-way answer -------------------
    assert ttl_none == -1, "TTL on a key with no expiry must return the integer -1"
    assert ttl_missing == -2, (
        "TTL on a key that does not exist must return the integer -2, distinctly from the "
        "-1 that means 'exists, no expiry'"
    )
    assert expire_reply == 1, "EXPIRE on an existing key must return the integer 1"
    assert isinstance(ttl, int), ttl
    assert 0 < ttl <= 100, (
        f"after EXPIRE 100 the TTL must be a countdown in (0, 100], got {ttl}; a stubbed "
        f"expiry that never counts down is not an expiry"
    )
    assert expire_missing == 0, "EXPIRE on a nonexistent key must return the integer 0, not 1"

    # ---- a type error must come back as a RESP error, not a success -------------
    assert str(incr_reply).startswith("-"), (
        f"INCR on a key holding a non-integer string must return a RESP error reply, got "
        f"{incr_reply!r}; silently succeeding is over-permissive"
    )
    assert "not an integer" in incr_reply or incr_reply.startswith("-ERR"), (
        f"the INCR type error must be an -ERR reply naming the integer problem, got "
        f"{incr_reply!r}"
    )
    # The error must not have disturbed the value.
    assert get_after_incr == expected_get, "a failed INCR mutated or cleared the key's value"

    # ---- an unknown command is refused, not swallowed ---------------------------
    assert str(unknown_reply).startswith("-"), (
        f"an unknown command must return a RESP error reply, got {unknown_reply!r}; an "
        f"endpoint that answers +OK to anything is not implementing the protocol"
    )

    # ---- delete: integer reply, idempotent second call --------------------------
    assert del_reply == 1, "DEL of an existing key must return 1"
    assert get_after_del is None, "GET after DEL must return the null bulk string"
    assert del_again == 0, "DEL of an already-deleted key must return 0, not 1"

    _delete_cluster_and_wait(ec, cluster_id)
    assert _describe_cluster(ec, cluster_id) is None, f"{cluster_id} still resolves after delete"


# ===== the in-VPC RESP probe =====
#
# The cache answers only inside its VPC, so the protocol round trip is carried there by a Lambda
# function in the run's network. The function has its own security group, and the cache's group
# admits only that group. The handler only drives sockets and reports what came back; every
# assertion lives in this file. It speaks RESP2 by hand, so it needs nothing beyond the Python
# standard library.

_PROBE_SRC = r'''
import socket, ssl


def _encode(args):
    out = [b"*%d\r\n" % len(args)]
    for arg in args:
        raw = arg.encode() if isinstance(arg, str) else bytes(arg)
        out.append(b"$%d\r\n%s\r\n" % (len(raw), raw))
    return b"".join(out)


class _Reader:
    def __init__(self, sock):
        self.sock, self.buf = sock, b""

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("the server closed the connection")
        self.buf += chunk

    def line(self):
        while b"\r\n" not in self.buf:
            self._fill()
        head, self.buf = self.buf.split(b"\r\n", 1)
        return head

    def exact(self, n):
        while len(self.buf) < n + 2:
            self._fill()
        data, self.buf = self.buf[:n], self.buf[n + 2:]
        return data

    def reply(self):
        head = self.line()
        kind, rest = head[:1], head[1:].decode("utf-8", "backslashreplace")
        if kind in (b"+", b"-"):
            return kind.decode() + rest
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            return None if n < 0 else "$" + self.exact(n).decode("utf-8", "backslashreplace")
        if kind == b"*":
            n = int(rest)
            return None if n < 0 else [self.reply() for _ in range(n)]
        raise ValueError("not a RESP2 reply: %r" % head[:60])


_TRUST = {"verify": True, "ca_pem": None}


def _connect(host, port, tls):
    sock = socket.create_connection((host, port), timeout=10)
    if not tls:
        return sock
    context = ssl.create_default_context(cadata=_TRUST["ca_pem"])
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=host)


def _session(host, port, spec):
    out = {"replies": [], "error": None}
    try:
        sock = _connect(host, port, spec.get("tls", True))
    except Exception as exc:
        out["error"] = "connect: %s: %s" % (type(exc).__name__, exc)
        return out
    try:
        reader = _Reader(sock)
        for command in spec["commands"]:
            sock.sendall(_encode(command))
            out["replies"].append(reader.reply())
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        sock.close()
    return out


def handler(event, context):
    host, port = event["host"], int(event["port"])
    _TRUST.update(verify=event["verify"], ca_pem=event["ca_pem"])
    return {"sessions": [_session(host, port, s) for s in event["sessions"]]}
'''

_LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_VPC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_FN_TIMEOUT_S = 120
#: Lambda releases a deleted function's network interfaces asynchronously, in up to 20 minutes
#: or sometimes longer, so the function is deleted as soon as the last session has run.
_ENI_WAIT_S = 1620


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _probe_open(ctx, net) -> dict:
    """Deploy the probe into the run's network with its own security group.

    Returns ``{"fn": <function name>, "sg": <group id>}``; the cache's group admits ``sg``. The
    teardown is registered before the first create. One subnet is enough to reach the whole VPC,
    and it keeps Lambda to one network interface.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-invpc-probe-")
    probe = {"fn": name, "role": name, "sg": None}
    ctx.on_cleanup(lambda: _probe_close(ctx, probe))
    probe["sg"] = ec2.create_security_group(
        GroupName=name,
        Description="sim2real in-VPC data-plane probe",
        VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Description="sim2real in-VPC data-plane probe",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_EXEC)
    # create_role returns before Lambda can assume the role, and no API reports when it can, so
    # the bounded retry sits on the first call that needs it.
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip(_PROBE_SRC)},
                Timeout=_FN_TIMEOUT_S,
                MemorySize=256,
                VpcConfig={"SubnetIds": net.subnet_ids[:1], "SecurityGroupIds": [probe["sg"]]},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if _err(exc) != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    deadline = time.monotonic() + 600
    while (cfg := lam.get_function_configuration(FunctionName=name))["State"] == "Pending":
        assert time.monotonic() < deadline, f"probe function {name} never left Pending"
        time.sleep(5)
    assert cfg["State"] == "Active", f"probe function {name} is {cfg['State']!r}: {cfg.get('StateReason')!r}"
    return probe


def _probe_call(ctx, probe: dict, host: str, port: int, sessions: list) -> list:
    """Run RESP ``sessions`` against ``host:port`` from inside the VPC; one result per session.

    A session is ``{"tls": bool, "commands": [[arg, ...], ...]}``; its result is
    ``{"replies": [...], "error": str | None}``. The function runs inside the VPC, so it dials the
    endpoint as published. A TLS session encrypts without verifying the
    server's identity, as SimParity's contract (Artifact TLS) requires of a non-HTTP data plane;
    the ``verify`` and ``ca_pem`` fields carry ``ctx.http_verify`` to the handler, which records
    them and never verifies against them.
    """
    port = int(port)
    verify = ctx.http_verify
    payload = {
        "host": host,
        "port": port,
        "sessions": sessions,
        "verify": verify is not False,
        "ca_pem": Path(verify).read_text() if isinstance(verify, str) else None,
    }
    lam = ctx.client("lambda", config=Config(read_timeout=_FN_TIMEOUT_S + 60))
    resp = lam.invoke(FunctionName=probe["fn"], Payload=json.dumps(payload).encode())
    out = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"the in-VPC probe raised: {out!r}"
    return out["sessions"]


def _probe_release(ctx, probe: dict) -> None:
    """Delete the function once the last session has run, so Lambda starts releasing its network
    interface while the rest of the check runs and tears down; ``_probe_close`` waits for it."""
    try:
        ctx.client("lambda").delete_function(FunctionName=probe["fn"])
    except ClientError as exc:
        if _err(exc) != "ResourceNotFoundException":
            raise


def _probe_close(ctx, probe: dict) -> None:
    """Delete the function, wait for its network interface to go, then its group, role and logs.

    Every step runs; the failures are raised together at the end.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name, sg = probe["fn"], probe["sg"]

    def enis_gone():
        # A detached interface Lambda has not reaped yet is deleted here; one still attached waits.
        deadline, refused, enis = time.monotonic() + _ENI_WAIT_S, [], []
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [sg]}])[
                "NetworkInterfaces"
            ]
            if not enis:
                return
            for eni in enis:
                if eni["Status"] == "available":
                    try:
                        ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                    except ClientError as exc:
                        refused.append(f"{eni['NetworkInterfaceId']}: {_err(exc)}")
            time.sleep(15)
        raise AssertionError(
            f"interfaces still in {sg} after {_ENI_WAIT_S}s: "
            f"{[(e['NetworkInterfaceId'], e['Status']) for e in enis]}; refused deletes: {refused}"
        )

    def group_gone():
        # A missing group is not success: the probe created it and only this step deletes it, so a
        # missing group means something else did, which the teardown reports.
        deadline = time.monotonic() + 300
        while True:
            try:
                ec2.delete_security_group(GroupId=sg)
                return
            except ClientError as exc:
                if _err(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(10)

    steps = [(f"function {name}", lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")]
    if sg:
        steps += [(f"interfaces of {sg}", enis_gone, None), (f"security group {sg}", group_gone, "InvalidGroup.NotFound")]
    steps += [
        (f"policy of role {name}", lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_EXEC), "NoSuchEntity"),
        (f"role {name}", lambda: iam.delete_role(RoleName=name), "NoSuchEntity"),
        (
            f"log group of {name}",
            lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"),
            "ResourceNotFoundException",
        ),
    ]
    failures = []
    for what, delete, gone in steps:
        try:
            delete()
        except ClientError as exc:
            if _err(exc) != gone:
                failures.append(f"{what}: {exc!r}")
        except Exception as exc:  # noqa: BLE001 - raised below, once every step was tried
            failures.append(f"{what}: {exc!r}")
    if failures:
        raise AssertionError(f"probe teardown left {len(failures)} resource(s): {failures}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
