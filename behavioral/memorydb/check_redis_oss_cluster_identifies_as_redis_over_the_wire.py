"""redis-oss-cluster-identifies-as-redis-over-the-wire."""
from __future__ import annotations

import io
import json
import secrets
import socket
import ssl
import time
import zipfile
from pathlib import Path

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redis-oss-cluster-identifies-as-redis-over-the-wire"
GROUP = "engine-identity"
SERVICES = ["memorydb"]

_NODE_TYPE = "db.t4g.small"
#: Pinned, because the engine's own replies (error strings, HELLO and INFO versions) are graded.
_ENGINE_VERSION = "7.1"
_CLUSTER_WAIT_S = 1500
#: The cluster's delete and its wait until gone; the ACL, user and subnet group get their own.
_RETIRE_WAIT_S = 900
_RELEASE_WAIT_S = 300
_FN_TIMEOUT_S = 120
#: Cluster states an operation passes through; anything else is settled.
_TRANSIENT = ("creating", "updating", "snapshotting", "modifying")


@tags(
    "axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane",
    "concern:negative-classes", "dp:native", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A MemoryDB cluster created with Engine="redis" speaks Redis OSS on the wire, not Valkey:
    HELLO and INFO name redis, and the 7.2 commands Valkey carries (ZRANK WITHSCORE, CLIENT
    NO-TOUCH, CLUSTER MYSHARDID) are unknown; only the socket shows which engine answers."""
    mdb = ctx.client("memorydb")
    net = ctx.network()
    base = ctx.unique_name("sim2real-mdbre-")
    res_tags = [{"Key": "sim2real", "Value": CHECK}]
    user, password = f"{base}-full", secrets.token_hex(24)

    ctx.on_cleanup(lambda: _teardown_estate(mdb, base, user))
    mdb.create_subnet_group(
        SubnetGroupName=base,
        Description="sim2real memorydb redis-identity estate",
        SubnetIds=net.subnet_ids,
        Tags=res_tags,
    )
    mdb.create_user(
        UserName=user,
        AccessString="on ~* &* +@all",
        AuthenticationMode={"Type": "password", "Passwords": [password]},
        Tags=res_tags,
    )
    mdb.create_acl(ACLName=base, UserNames=[user], Tags=res_tags)
    _poll(
        lambda: _describe_acl(mdb, base),
        lambda acl: acl is not None and acl["Status"] == "active",
        300, 5, f"ACL {base} never became active",
    )
    mdb.create_cluster(
        ClusterName=base,
        Description="sim2real memorydb redis-identity estate",
        NodeType=_NODE_TYPE,
        Engine="redis",
        EngineVersion=_ENGINE_VERSION,
        NumShards=1,
        NumReplicasPerShard=0,
        ACLName=base,
        SubnetGroupName=base,
        SecurityGroupIds=[net.security_group_id],
        TLSEnabled=True,
        SnapshotRetentionLimit=0,
        Tags=res_tags,
    )
    cluster = _poll(
        lambda: _describe_cluster(mdb, base),
        lambda c: c is not None and c["Status"] != "creating",
        _CLUSTER_WAIT_S, 2, f"cluster {base} never left creating",
    )
    assert cluster["Status"] == "available", (
        f"cluster {base} left creating as {cluster['Status']!r}, not available"
    )
    assert cluster["Engine"] == "redis", f"the cluster describes its engine as {cluster['Engine']!r}"
    assert cluster["EngineVersion"] == _ENGINE_VERSION, (
        f"the cluster describes its engine version as {cluster['EngineVersion']!r}"
    )
    endpoint = cluster["ClusterEndpoint"]
    host, port = endpoint["Address"], endpoint["Port"]

    fn = _deploy_probe(ctx, net)
    body = _invoke(
        ctx,
        fn,
        {
            "host": host,
            "port": port,
            "sessions": [
                {
                    "tls": True,
                    "commands": [
                        ["AUTH", user, password],
                        ["HELLO", "2"],
                        ["INFO", "server"],
                        ["SET", "{sim2real-probe}:key", "v1"],
                        ["GET", "{sim2real-probe}:key"],
                        ["ZADD", "{sim2real-probe}:zset", "1", "a"],
                        ["ZRANK", "{sim2real-probe}:zset", "a", "WITHSCORE"],
                        ["CLIENT", "NO-TOUCH", "ON"],
                        ["CLUSTER", "MYSHARDID"],
                        ["DEL", "{sim2real-probe}:key", "{sim2real-probe}:zset"],
                    ],
                }
            ],
        },
    )
    (session,) = body["sessions"]
    assert session["error"] is None, (
        f"DATAPLANE_UNIMPLEMENTED: the RESP session broke after {session['replies']!r}: "
        f"{session['error']}"
    )
    r = session["replies"]
    assert len(r) == 10, f"expected 10 replies, the probe returned {r!r}"

    hello = dict(zip(r[1][0::2], r[1][1::2], strict=True))
    server_info = _info(r[2])
    observed = {
        "auth": r[0],
        "hello_server": hello.get("$server"),
        "hello_mode": hello.get("$mode"),
        "hello_version_matches_cluster": str(hello.get("$version", "$"))[1:].startswith(_ENGINE_VERSION),
        "info_redis_version_matches_cluster": server_info.get("redis_version", "").startswith(
            _ENGINE_VERSION
        ),
        "info_has_valkey_version": "valkey_version" in server_info,
        "set": r[3],
        "get": r[4],
        "zadd_count": r[5],
        "zrank_withscore": r[6],
        "client_no_touch": r[7],
        "cluster_myshardid": r[8],
        "del_count": r[9],
    }
    expected = {
        "auth": "+OK",
        "hello_server": "$redis",
        "hello_mode": "$cluster",
        "hello_version_matches_cluster": True,
        "info_redis_version_matches_cluster": True,
        "info_has_valkey_version": False,
        "set": "+OK",
        "get": "$v1",
        "zadd_count": 1,
        "zrank_withscore": "-ERR wrong number of arguments for 'zrank' command",
        "client_no_touch": "-ERR unknown subcommand 'NO-TOUCH'. Try CLIENT HELP.",
        "cluster_myshardid": "-ERR unknown subcommand 'MYSHARDID'. Try CLUSTER HELP.",
        "del_count": 2,
    }
    assert observed == expected, f"observed {observed!r} for EngineVersion {cluster['EngineVersion']!r}"


# ===== helpers =====

def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _poll(probe, done, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"TARGET_STATE_UNIMPLEMENTED: {what} within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _describe_cluster(mdb, name: str):
    try:
        return mdb.describe_clusters(ClusterName=name, ShowShardDetails=True)["Clusters"][0]
    except ClientError as exc:
        if _code(exc) == "ClusterNotFoundFault":
            return None
        raise


def _describe_acl(mdb, name: str):
    try:
        return mdb.describe_acls(ACLName=name)["ACLs"][0]
    except ClientError as exc:
        if _code(exc) == "ACLNotFoundFault":
            return None
        raise


def _delete_until_gone(fn, gone_code: str, busy_codes: tuple, deadline: float) -> None:
    """``fn()`` until it succeeds or reports the resource gone; a busy resource is retried."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) == gone_code:
                return
            if _code(exc) not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _until_gone(fn, gone_code: str, busy_code: str):
    """A delete step: ``fn()`` retried while busy until a deadline, as ``_delete_until_gone``."""
    return lambda deadline: _delete_until_gone(fn, gone_code, (busy_code,), deadline)


def _retire_cluster(mdb, name: str, deadline: float) -> None:
    """Delete the cluster, retrying while it is busy, and wait until it is gone."""
    while True:
        try:
            mdb.delete_cluster(ClusterName=name)
            break
        except ClientError as exc:
            if _code(exc) == "ClusterNotFoundFault":
                break
            current = _describe_cluster(mdb, name)
            if current is None or current["Status"] == "deleting":
                break
            if _code(exc) != "InvalidClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _poll(
        lambda: _describe_cluster(mdb, name),
        lambda c: c is None,
        max(0.0, deadline - time.monotonic()), 2, f"cluster {name} was not deleted",
    )


def _teardown_estate(mdb, base: str, user: str) -> None:
    """Retire the cluster, then always try the ACL, the user and the subnet group.

    Each failure is collected and raised together at the end, so one leak never hides another.
    """
    deletes = [
        (f"cluster {base}", lambda deadline: _retire_cluster(mdb, base, deadline)),
        (
            f"ACL {base}",
            _until_gone(lambda: mdb.delete_acl(ACLName=base), "ACLNotFoundFault", "InvalidACLStateFault"),
        ),
        (
            f"user {user}",
            _until_gone(lambda: mdb.delete_user(UserName=user), "UserNotFoundFault", "InvalidUserStateFault"),
        ),
        (
            f"subnet group {base}",
            _until_gone(
                lambda: mdb.delete_subnet_group(SubnetGroupName=base),
                "SubnetGroupNotFoundFault",
                "SubnetGroupInUseFault",
            ),
        ),
    ]
    failures = []
    deadline = time.monotonic() + _RETIRE_WAIT_S
    for i, (what, delete) in enumerate(deletes):
        try:
            delete(deadline)
        except Exception as exc:  # noqa: BLE001 - raised below, once every delete was tried
            failures.append(f"{what}: {exc!r}")
        if i == 0:  # the rest share their own window, from when the cluster is gone or given up
            deadline = time.monotonic() + _RELEASE_WAIT_S
    if failures:
        raise AssertionError(f"teardown left {len(failures)} resource(s): {failures}")


def _info(bulk: str) -> dict:
    """``key:value`` lines of an INFO bulk reply."""
    assert isinstance(bulk, str) and bulk.startswith("$"), f"expected a bulk reply, got {bulk!r}"
    pairs = (ln.split(":", 1) for ln in bulk[1:].splitlines() if ":" in ln and not ln.startswith("#"))
    return {k.strip(): v.strip() for k, v in pairs}


# ===== the in-VPC RESP probe =====
#
# The cluster answers only inside its VPC, so the protocol round trip is carried there by a
# Lambda function in the run's network. The handler only drives sockets and reports what came
# back; every assertion lives in this file. It speaks RESP2 by hand over TLS, so it needs
# nothing beyond the Python standard library.

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


def _zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _reap_log_group(ctx, fn: str) -> None:
    """delete_function leaves /aws/lambda/<fn>, and a late flush can recreate it: reap in rounds."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn}"
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if _code(exc) != "ResourceNotFoundException":
                raise
        time.sleep(5)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after delete")


def _delete_function(lam, fn: str) -> None:
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as exc:
        if _code(exc) != "ResourceNotFoundException":
            raise


def _deploy_probe(ctx, net) -> str:
    """Deploy the RESP probe into the run's network, beside the cluster; return its name."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    role = ctx.unique_name("sim2real-mdb-probe-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Description="sim2real in-VPC MemoryDB RESP probe",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC))
    fn = ctx.unique_name("sim2real-mdb-probe-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, fn))
    # create_role returns before Lambda can assume the role, and no API reports when it can, so
    # the bounded retry sits on the first call that needs it.
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=fn,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip(_PROBE_SRC)},
                Timeout=_FN_TIMEOUT_S,
                MemorySize=256,
                VpcConfig={"SubnetIds": net.subnet_ids, "SecurityGroupIds": [net.security_group_id]},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if _code(exc) != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_function(lam, fn))
    _poll(
        lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] != "Pending",
        600, 5, f"probe function {fn} never left Pending",
    )
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert cfg["State"] == "Active", f"probe function {fn} is {cfg['State']!r}: {cfg.get('StateReason')!r}"
    return fn


def _invoke(ctx, fn: str, payload: dict) -> dict:
    """Invoke the in-VPC probe on the cluster's endpoint, verifying TLS as ``ctx.http_verify``.

    The function runs inside the VPC, so it dials the endpoint as published.
    """
    verify = ctx.http_verify
    payload = {
        **payload,
        "port": int(payload["port"]),
        "verify": verify is not False,
        "ca_pem": Path(verify).read_text() if isinstance(verify, str) else None,
    }
    lam = ctx.client("lambda", config=Config(read_timeout=_FN_TIMEOUT_S + 60))
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
    out = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"the in-VPC probe raised: {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
