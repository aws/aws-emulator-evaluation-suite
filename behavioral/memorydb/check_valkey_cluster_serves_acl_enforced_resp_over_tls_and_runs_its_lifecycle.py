"""valkey-cluster-serves-acl-enforced-resp-over-tls-and-runs-its-lifecycle."""
from __future__ import annotations

import base64
import io
import json
import secrets
import time
import zipfile
from pathlib import Path

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "valkey-cluster-serves-acl-enforced-resp-over-tls-and-runs-its-lifecycle"
GROUP = 'live-cluster'
SERVICES = ['memorydb']

# A native data-plane FAIL marker: a check detail carrying it is a fidelity failure, not an
# unhealthy environment, even when the message quotes a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# A resource the target accepted and never brought to its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


# ===== the estate ================================================================================
#
# A subnet group in the run's network, four users with distinct access strings, an ACL holding
# them, and a single-shard, replica-free TLS cluster on the smallest node type. A MemoryDB cluster
# takes many minutes to create, so one cluster per engine carries every probe that needs it.

_NODE_TYPE = "db.t4g.small"
#: Pinned, because the engine's own replies (error strings, HELLO and INFO versions) are graded.
_ENGINE_VERSION = "7.3"
_CLUSTER_WAIT_S = 1500
#: The cluster's delete and its wait until gone; the ACL, users and subnet group get their own.
_RETIRE_WAIT_S = 900
_RELEASE_WAIT_S = 300
_ACCESS = {
    "full": "on ~* &* +@all",
    "read": "on ~* &* -@all +@read",
    "keys": "on ~app:* &* +@all",
    "off": "off ~* &* +@all",
}
#: Cluster states an operation passes through; anything else is settled.
_TRANSIENT = ("creating", "updating", "snapshotting", "modifying")


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _msg(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message", "")


def _outcome(fn) -> tuple[str, str]:
    """``("accepted", "")`` when ``fn`` succeeds, else the (code, message) it was refused with."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc), _msg(exc)
    return "accepted", ""


def _poll(probe, done, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{STATE_MARKER}: {what} within {timeout_s}s; last saw {last!r}")
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


def _settled(mdb, name: str, timeout_s: float = 900) -> dict:
    return _poll(
        lambda: _describe_cluster(mdb, name),
        lambda c: c is not None and c["Status"] not in _TRANSIENT,
        timeout_s,
        15,
        f"cluster {name} never settled",
    )


def _create_estate(ctx, engine: str) -> dict:
    """Create the estate for ``engine``; its teardown is registered before the first create."""
    mdb = ctx.client("memorydb")
    net = ctx.network()
    base = ctx.unique_name(f"sim2real-mdb{engine[:2]}-")
    tags_ = [{"Key": "sim2real", "Value": CHECK}]
    users = {role: (f"{base}-{role}", secrets.token_hex(24)) for role in _ACCESS}
    estate = {"name": base, "engine": engine, "users": users}
    ctx.on_cleanup(lambda: _teardown_estate(mdb, estate))
    mdb.create_subnet_group(
        SubnetGroupName=base,
        Description="sim2real memorydb estate",
        SubnetIds=net.subnet_ids,
        Tags=tags_,
    )
    for role, access in _ACCESS.items():
        user, password = users[role]
        mdb.create_user(
            UserName=user,
            AccessString=access,
            AuthenticationMode={"Type": "password", "Passwords": [password]},
            Tags=tags_,
        )
    mdb.create_acl(ACLName=base, UserNames=[u for u, _ in users.values()], Tags=tags_)
    _poll(
        lambda: _describe_acl(mdb, base),
        lambda acl: acl is not None and acl["Status"] == "active",
        300,
        5,
        f"ACL {base} never became active",
    )
    mdb.create_cluster(
        ClusterName=base,
        Description="sim2real memorydb estate",
        NodeType=_NODE_TYPE,
        Engine=engine,
        EngineVersion=_ENGINE_VERSION,
        NumShards=1,
        NumReplicasPerShard=0,
        ACLName=base,
        SubnetGroupName=base,
        SecurityGroupIds=[net.security_group_id],
        TLSEnabled=True,
        SnapshotRetentionLimit=0,
        Tags=tags_,
    )
    return estate


def _await_estate(mdb, estate: dict) -> dict:
    """Poll the estate's cluster out of creating; it must be available, with an endpoint."""
    cluster = _poll(
        lambda: _describe_cluster(mdb, estate["name"]),
        lambda c: c is not None and c["Status"] != "creating",
        _CLUSTER_WAIT_S,
        20,
        f"cluster {estate['name']} never left creating",
    )
    assert cluster["Status"] == "available", (
        f"{STATE_MARKER}: cluster {estate['name']} left creating as {cluster['Status']!r}"
    )
    endpoint = cluster["ClusterEndpoint"]
    estate["host"], estate["port"] = endpoint["Address"], endpoint["Port"]
    return cluster


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
        max(0.0, deadline - time.monotonic()),
        2,
        f"cluster {name} was not deleted",
    )


def _teardown_estate(mdb, estate: dict) -> None:
    """Retire the cluster, then always try the ACL, the users and the subnet group.

    Each failure is collected and raised together at the end, so one leak never hides another.
    """
    base = estate["name"]
    deletes = [
        (f"cluster {base}", lambda deadline: _retire_cluster(mdb, base, deadline)),
        (
            f"ACL {base}",
            _until_gone(lambda: mdb.delete_acl(ACLName=base), "ACLNotFoundFault", "InvalidACLStateFault"),
        ),
        *(
            (
                f"user {user}",
                _until_gone(
                    lambda u=user: mdb.delete_user(UserName=u), "UserNotFoundFault", "InvalidUserStateFault"
                ),
            )
            for user, _ in estate["users"].values()
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


# ===== the in-VPC RESP probe =====================================================================
#
# The cluster answers only inside its VPC, so the protocol round trip is carried there by a
# Lambda function in the run's network. The handler only drives sockets and reports what came
# back; every assertion lives in this file. It speaks RESP2 by hand over TLS (or plain TCP when a
# session asks for it), so it needs nothing beyond the Python standard library.

_PROBE_SRC = r'''
import base64, socket, ssl


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


def _raw(host, port, spec):
    """Send bytes over plain TCP and report what came back and how the exchange ended."""
    out = {"received": "", "end": None}
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as exc:
        out["end"] = "connect: %s: %s" % (type(exc).__name__, exc)
        return out
    got = b""
    try:
        sock.sendall(base64.b64decode(spec["send"]))
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                out["end"] = "eof"
                break
            got += chunk
    except socket.timeout:
        out["end"] = "timeout"
    except Exception as exc:
        out["end"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        sock.close()
    out["received"] = base64.b64encode(got).decode()
    return out


def handler(event, context):
    host, port = event["host"], int(event["port"])
    _TRUST.update(verify=event["verify"], ca_pem=event["ca_pem"])
    if "raw" in event:
        return {"raw": _raw(host, port, event["raw"])}
    return {"sessions": [_session(host, port, s) for s in event["sessions"]]}
'''

_FN_TIMEOUT_S = 120
_LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
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


def _deploy_probe(ctx) -> str:
    """Deploy the RESP probe into the run's network, beside the cluster; return its name."""
    net = ctx.network()
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    role = ctx.unique_name("sim2real-mdb-probe-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Description="sim2real in-VPC MemoryDB probe",
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
        600,
        5,
        f"probe function {fn} never left Pending",
    )
    cfg = lam.get_function_configuration(FunctionName=fn)
    assert cfg["State"] == "Active", (
        f"probe function {fn} is {cfg['State']!r}: {cfg.get('StateReason')!r}"
    )
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
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"the in-VPC probe raised: {body!r}"
    return body


def _resp(ctx, fn: str, estate: dict, *sessions: list) -> list:
    """Run each session (a list of commands) on its own TLS connection; return their replies.

    A session whose connection fails reports it as a data-plane failure.
    """
    body = _invoke(
        ctx,
        fn,
        {
            "host": estate["host"],
            "port": estate["port"],
            "sessions": [{"tls": True, "commands": s} for s in sessions],
        },
    )
    out = []
    for spec, got in zip(sessions, body["sessions"], strict=True):
        assert got["error"] is None, (
            f"{DATAPLANE_MARKER}: session {spec!r} broke after {got['replies']!r}: {got['error']}"
        )
        out.append(got["replies"])
    return out


def _auth(estate: dict, role: str) -> list:
    user, password = estate["users"][role]
    return ["AUTH", user, password]


def _ready(ctx, engine: str) -> tuple[dict, str, dict]:
    """Create the estate and deploy the probe; return (estate, probe, the available cluster).

    The cluster is awaited even when the probe fails to deploy, so its teardown never meets a
    cluster that is still creating.
    """
    estate = _create_estate(ctx, engine)
    try:
        fn = _deploy_probe(ctx)
    finally:
        cluster = _await_estate(ctx.client("memorydb"), estate)
    return estate, fn, cluster


# The commands MemoryDB documents as unavailable, in forms that would change nothing if one ran.
# SHUTDOWN, SYNC, PSYNC and CLUSTER DELSLOTS are documented too and deliberately left out: if
# any were wrongly served, it would take the cluster down or start a replication stream.
_RESTRICTED = [
    ["CONFIG", "GET", "maxmemory"],
    ["BGSAVE"],
    ["SAVE"],
    ["BGREWRITEAOF"],
    ["DEBUG", "SLEEP", "0"],
    ["MODULE", "LIST"],
    ["ACL", "SETUSER", "sim2real-never-created"],
    ["ACL", "DELUSER", "sim2real-never-created"],
    ["ACL", "SAVE"],
    ["ACL", "LOAD"],
    ["REPLICAOF", "NO", "ONE"],
    ["SLAVEOF", "NO", "ONE"],
    ["MIGRATE", "127.0.0.1", "1", "sim2real-never-created", "0", "100"],
    ["CLUSTER", "SETSLOT", "0", "STABLE"],
]


def _unknown_command(cmd: list[str]) -> str:
    """The RESP error MemoryDB answers a disabled command with.

    A disabled top-level command names itself and its args; MemoryDB answers a disabled
    subcommand of a container command it otherwise serves (``ACL``, ``CLUSTER``) by naming only
    the container, exactly as it answers a container name on its own.
    """
    if cmd[0] in ("ACL", "CLUSTER"):
        return f"-ERR unknown command '{cmd[0]}'"
    args = "".join(f"'{a}' " for a in cmd[1:])
    return f"-ERR unknown command '{cmd[0]}', with args beginning with: {args}"


def _crc16(data: bytes) -> int:
    """CRC16-CCITT (XMODEM), the hash the cluster specification assigns keys to slots with."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def _slot(key: str) -> int:
    raw = key.encode()
    start = raw.find(b"{")
    if start != -1:
        end = raw.find(b"}", start + 1)
        if end > start + 1:
            raw = raw[start + 1 : end]
    return _crc16(raw) % 16384


def _is_resp(data: bytes) -> bool:
    """True when ``data`` opens with a complete RESP2 or RESP3 reply header line."""
    head, sep, _ = data.partition(b"\r\n")
    return bool(sep) and len(head) >= 1 and head[:1] in _RESP_TYPES


#: The first byte of every RESP2 and RESP3 reply type.
_RESP_TYPES = {bytes([c]) for c in b"+-:$*_,#!=(%~>|"}


def _info(reply) -> dict:
    """``key:value`` lines of an INFO / CLUSTER INFO bulk reply; a non-bulk reply is kept as is."""
    if not (isinstance(reply, str) and reply.startswith("$")):
        return {"reply": reply}
    pairs = (ln.split(":", 1) for ln in reply[1:].splitlines() if ":" in ln and not ln.startswith("#"))
    return {k.strip(): v.strip() for k, v in pairs}


def _pairs(reply) -> dict:
    """A flat RESP2 key/value array (HELLO) as a dict; a non-array reply is kept as is."""
    if not isinstance(reply, list):
        return {"reply": reply}
    return dict(zip(reply[0::2], reply[1::2], strict=True))


def _describe_snapshot(mdb, name: str):
    try:
        return mdb.describe_snapshots(SnapshotName=name, ShowDetail=True)["Snapshots"][0]
    except ClientError as exc:
        if _code(exc) == "SnapshotNotFoundFault":
            return None
        raise


def _drop_snapshot(mdb, name: str) -> None:
    _delete_until_gone(
        lambda: mdb.delete_snapshot(SnapshotName=name),
        "SnapshotNotFoundFault",
        ("InvalidSnapshotStateFault",),
        time.monotonic() + 300,
    )


_SNAPSHOT_WAIT_S = 1800


def _settled_snapshot(mdb, name: str) -> dict:
    return _poll(
        lambda: _describe_snapshot(mdb, name),
        lambda s: s is not None and s["Status"] not in ("creating", "copying"),
        _SNAPSHOT_WAIT_S,
        15,
        f"snapshot {name} never settled",
    )


def _data_plane(ctx, fn: str, estate: dict) -> tuple[dict, dict]:
    """Every RESP probe of the cluster: (what was seen, what MemoryDB documents) per probe."""
    users = {role: user for role, (user, _) in estate["users"].items()}
    passwords = {role: password for role, (_, password) in estate["users"].items()}
    sfx = ctx.unique_name("k-")
    anon_key, ro_key = f"app:{sfx}:anon", f"app:{sfx}:ro"
    inside, outside = f"app:{sfx}:in", f"other:{sfx}:out"
    tag = "{" + sfx + "}"
    s, c, h, l, st, z, x = (f"app:{tag}:{n}" for n in ("s", "c", "h", "l", "set", "z", "x"))
    first = f"app:{sfx}:xa"
    second = next(f"app:{sfx}:xb{i}" for i in range(1000) if _slot(f"app:{sfx}:xb{i}") != _slot(first))
    paired = (f"app:{tag}:pa", f"app:{tag}:pb")
    noauth = "-NOAUTH Authentication required."
    wrongpass = "-WRONGPASS invalid username-password pair or user is disabled."
    seen, want = {}, {}

    ping = base64.b64encode(b"*1\r\n$4\r\nPING\r\n").decode()
    raw = _invoke(ctx, fn, {"host": estate["host"], "port": estate["port"], "raw": {"send": ping}})["raw"]
    received = base64.b64decode(raw["received"])
    seen["cleartext PING to the TLS endpoint"] = {
        "connected": not str(raw["end"]).startswith("connect:"),
        "answered in RESP": _is_resp(received),
    }
    # A TLS-only listener does not speak RESP in the clear. Whether it waits, closes or sends a
    # TLS alert is its own choice; only a reply that parses as RESP would be wrong.
    want["cleartext PING to the TLS endpoint"] = {"connected": True, "answered in RESP": False}

    sessions = {
        "unauthenticated, then the default user": (
            [["PING"], ["SET", anon_key, "v"], ["AUTH", "default", "sim2real-not-a-password"]],
            [noauth, noauth, wrongpass],
        ),
        "wrong password, disabled user, unknown user, then the right one": (
            [
                ["AUTH", users["full"], "sim2real-wrong-password-0000"],
                ["PING"],
                ["AUTH", users["off"], passwords["off"]],
                ["PING"],
                ["AUTH", f"{estate['name']}-nobody", passwords["full"]],
                ["AUTH", users["full"], passwords["full"]],
                ["ACL", "WHOAMI"],
                ["EXISTS", anon_key],
                ["SET", ro_key, "v1"],
            ],
            [wrongpass, noauth, wrongpass, noauth, wrongpass, "+OK", f"${users['full']}", 0, "+OK"],
        ),
        "a +@read user reads and is refused writes": (
            [_auth(estate, "read"), ["GET", ro_key], ["SET", ro_key, "v2"], ["DEL", ro_key], ["GET", ro_key]],
            [
                "+OK",
                "$v1",
                f"-NOPERM User {users['read']} has no permissions to run the 'set' command",
                f"-NOPERM User {users['read']} has no permissions to run the 'del' command",
                "$v1",
            ],
        ),
        "a ~app:* user is refused keys outside its pattern": (
            [_auth(estate, "keys"), ["SET", inside, "in"], ["SET", outside, "out"], ["GET", outside], ["GET", inside]],
            [
                "+OK",
                "+OK",
                "-NOPERM No permissions to access a key",
                "-NOPERM No permissions to access a key",
                "$in",
            ],
        ),
        "the refusals left the keys as they were": (
            [_auth(estate, "full"), ["GET", ro_key], ["EXISTS", outside], ["DEL", ro_key], ["DEL", inside]],
            ["+OK", "$v1", 0, 1, 1],
        ),
        "restricted commands, then supported ones": (
            [_auth(estate, "full"), *_RESTRICTED, ["ACL", "WHOAMI"], ["PING"]],
            [
                "+OK",
                *(_unknown_command(cmd) for cmd in _RESTRICTED),
                f"${users['full']}",
                "+PONG",
            ],
        ),
        "core data types round-trip": (
            [
                _auth(estate, "full"),
                ["SET", s, "héllo"],
                ["GET", s],
                ["APPEND", s, "!"],
                ["STRLEN", s],
                ["INCR", c],
                ["INCRBY", c, "41"],
                ["HSET", h, "f1", "a", "f2", "b"],
                ["HGET", h, "f2"],
                ["HINCRBY", h, "n", "5"],
                ["HLEN", h],
                ["RPUSH", l, "a", "b", "c"],
                ["LPOP", l],
                ["LRANGE", l, "0", "-1"],
                ["SADD", st, "a", "b", "a"],
                ["SISMEMBER", st, "a"],
                ["SCARD", st],
                ["ZADD", z, "2", "b", "1", "a"],
                ["ZINCRBY", z, "5", "a"],
                ["ZRANGE", z, "0", "-1", "WITHSCORES"],
                ["XADD", x, "1-1", "field", "value"],
                ["XLEN", x],
                ["XRANGE", x, "-", "+"],
                ["EXPIRE", s, "300"],
                ["PERSIST", s],
                ["TTL", s],
                ["MULTI"],
                ["INCR", c],
                ["HSET", h, "f3", "c"],
                ["EXEC"],
                ["TYPE", s],
                ["TYPE", h],
                ["TYPE", l],
                ["TYPE", st],
                ["TYPE", z],
                ["TYPE", x],
                ["DEL", s, c, h, l, st, z, x],
                ["EXISTS", s, c, h, l, st, z, x],
            ],
            [
                "+OK", "+OK", "$héllo", 7, 7, 1, 42, 2, "$b", 5, 3, 3, "$a", ["$b", "$c"], 2, 1, 2,
                2, "$6", ["$b", "$2", "$a", "$6"], "$1-1", 1, [["$1-1", ["$field", "$value"]]], 1, 1,
                -1, "+OK", "+QUEUED", "+QUEUED", [43, 1], "+string", "+hash", "+list", "+set",
                "+zset", "+stream", 7, 0,
            ],
        ),
        "hash slots: KEYSLOT, CROSSSLOT, and a hash tag": (
            [
                _auth(estate, "full"),
                ["CLUSTER", "KEYSLOT", first],
                ["CLUSTER", "KEYSLOT", second],
                ["CLUSTER", "KEYSLOT", paired[0]],
                ["MSET", first, "1", second, "2"],
                ["EXISTS", first],
                ["EXISTS", second],
                ["MSET", paired[0], "1", paired[1], "2"],
                ["MGET", *paired],
                ["DEL", *paired],
            ],
            [
                "+OK",
                _slot(first),
                _slot(second),
                _slot(paired[0]),
                "-CROSSSLOT Keys in request don't hash to the same slot",
                0,
                0,
                "+OK",
                ["$1", "$2"],
                2,
            ],
        ),
    }
    engine = [_auth(estate, "full"), ["CLUSTER", "INFO"], ["CLUSTER", "SLOTS"], ["HELLO", "2"], ["INFO", "server"]]
    replies = _resp(ctx, fn, estate, *(cmds for cmds, _ in sessions.values()), engine)
    for (label, (_, expected)), got in zip(sessions.items(), replies, strict=False):
        seen[label], want[label] = got, expected
    engine_replies = replies[-1]
    seen["AUTH before the engine probes"], want["AUTH before the engine probes"] = engine_replies[0], "+OK"
    info = _info(engine_replies[1])
    seen["CLUSTER INFO"] = {k: info.get(k) for k in ("cluster_state", "cluster_slots_assigned", "cluster_size", "cluster_known_nodes")}
    want["CLUSTER INFO"] = {"cluster_state": "ok", "cluster_slots_assigned": "16384", "cluster_size": "1", "cluster_known_nodes": "1"}
    slots = engine_replies[2]
    seen["CLUSTER SLOTS ranges and ports"] = [(r[0], r[1], r[2][1]) for r in slots] if isinstance(slots, list) else slots
    want["CLUSTER SLOTS ranges and ports"] = [(0, 16383, estate["port"])]
    estate["hello"], estate["info"] = _pairs(engine_replies[3]), _info(engine_replies[4])
    return seen, want


def _control_plane(ctx, mdb, estate: dict) -> tuple[dict, dict]:
    """The live cluster's control plane: name, settings, refusals, and a snapshot lifecycle."""
    name = estate["name"]
    net = ctx.network()
    seen, want = {}, {}
    _settled(mdb, name)

    seen["CreateCluster under a name in use"] = _outcome(
        lambda: mdb.create_cluster(
            ClusterName=name,
            NodeType="db.t4g.medium",
            ACLName=name,
            SubnetGroupName=name,
            NumShards=1,
            NumReplicasPerShard=0,
        )
    )
    want["CreateCluster under a name in use"] = (
        "ClusterAlreadyExistsFault",
        "Cluster with specified name already exists.",
    )
    seen["node type after the refused duplicate"] = _describe_cluster(mdb, name)["NodeType"]
    want["node type after the refused duplicate"] = _NODE_TYPE

    description = f"sim2real lifecycle {ctx.unique_name('d-')}"
    mdb.update_cluster(
        ClusterName=name,
        Description=description,
        SnapshotWindow="03:00-04:00",
        MaintenanceWindow="sun:05:00-sun:06:00",
    )
    updated = _settled(mdb, name)
    seen["settings after UpdateCluster"] = {
        k: updated.get(k) for k in ("Status", "Description", "SnapshotWindow", "MaintenanceWindow")
    }
    want["settings after UpdateCluster"] = {
        "Status": "available",
        "Description": description,
        "SnapshotWindow": "03:00-04:00",
        "MaintenanceWindow": "sun:05:00-sun:06:00",
    }

    seen["a 30-minute maintenance window"] = _outcome(
        lambda: mdb.update_cluster(ClusterName=name, MaintenanceWindow="mon:05:00-mon:05:30")
    )
    want["a 30-minute maintenance window"] = (
        "InvalidParameterValueException",
        "Maintenance window must be at least 60 minutes.",
    )
    seen["maintenance window after the refusal"] = _settled(mdb, name)["MaintenanceWindow"]
    want["maintenance window after the refusal"] = "sun:05:00-sun:06:00"

    shard = updated["Shards"][0]["Name"]
    seen["FailoverShard on a shard with no replica"] = _outcome(
        lambda: mdb.failover_shard(ClusterName=name, ShardName=shard)
    )
    want["FailoverShard on a shard with no replica"] = (
        "InvalidParameterCombinationException",
        f"Shard {shard} needs a replica in order to invoke failover-shard API",
    )
    _settled(mdb, name)

    snapshot = ctx.unique_name("sim2real-mdb-snap-")
    created = mdb.create_snapshot(
        ClusterName=name, SnapshotName=snapshot, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Snapshot"]
    ctx.on_cleanup(lambda: _drop_snapshot(mdb, snapshot))
    seen["cluster status once CreateSnapshot returns"] = _describe_cluster(mdb, name)["Status"]
    want["cluster status once CreateSnapshot returns"] = "snapshotting"
    seen["CreateSnapshot answer"] = (created["Name"], created["Source"])
    want["CreateSnapshot answer"] = (snapshot, "manual")
    # The developer guide's snapshot constraints: no other operation runs on the cluster while
    # its snapshot is being taken.
    seen["UpdateCluster while the snapshot runs"] = _outcome(
        lambda: mdb.update_cluster(ClusterName=name, Description=f"{description} during snapshot")
    )
    want["UpdateCluster while the snapshot runs"] = (
        "InvalidClusterStateFault",
        "Cluster must be in available state to modify.",
    )

    done = _settled_snapshot(mdb, snapshot)
    config = done["ClusterConfiguration"]
    seen["the finished snapshot"] = {
        "Status": done["Status"],
        "Source": done["Source"],
        "Name": config.get("Name"),
        "Engine": config.get("Engine"),
        "NodeType": config.get("NodeType"),
        "NumShards": config.get("NumShards"),
        "VpcId": config.get("VpcId"),
        "SubnetGroupName": config.get("SubnetGroupName"),
        "Port": config.get("Port"),
        "SnapshotWindow": config.get("SnapshotWindow"),
        "MaintenanceWindow": config.get("MaintenanceWindow"),
        "ShardSlots": [s.get("Configuration", {}).get("Slots") for s in config.get("Shards", [])],
    }
    want["the finished snapshot"] = {
        "Status": "available",
        "Source": "manual",
        "Name": name,
        "Engine": "valkey",
        "NodeType": _NODE_TYPE,
        "NumShards": 1,
        "VpcId": net.vpc_id,
        "SubnetGroupName": name,
        "Port": estate["port"],
        "SnapshotWindow": "03:00-04:00",
        "MaintenanceWindow": "sun:05:00-sun:06:00",
        "ShardSlots": ["0-16383"],
    }

    _settled(mdb, name)
    seen["a second snapshot under the same name"] = _outcome(
        lambda: mdb.create_snapshot(ClusterName=name, SnapshotName=snapshot)
    )
    want["a second snapshot under the same name"] = (
        "SnapshotAlreadyExistsFault",
        "Snapshot with specified name already exists.",
    )

    # CopySnapshot is left out: it would cost a second multi-minute snapshot-settle wait on top of
    # the one above, which the check's budget does not carry.
    _drop_snapshot(mdb, snapshot)
    _poll(lambda: _describe_snapshot(mdb, snapshot), lambda s: s is None, 300, 10, f"snapshot {snapshot} was never removed")
    seen["DescribeSnapshots after the delete"] = _outcome(lambda: mdb.describe_snapshots(SnapshotName=snapshot))
    want["DescribeSnapshots after the delete"] = (
        "SnapshotNotFoundFault",
        f"Snapshot with name {snapshot} not found",
    )
    return seen, want


@tags(
    "axis:happy-path", "cap:c2", "cap:c4", "cap:c7", "concern:data-plane",
    "concern:negative-classes", "concern:representation", "dp:native", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A Valkey cluster serves RESP only over TLS with its ACL's users, passwords, categories and key
    patterns enforced, DescribeClusters matches what the engine serves, and its control plane refuses
    and applies updates, failover and snapshot as documented; every differing probe is listed.
    """
    estate, fn, cluster = _ready(ctx, "valkey")
    mdb = ctx.client("memorydb")
    net = ctx.network()
    (shard,) = cluster["Shards"]
    (node,) = shard["Nodes"]
    seen = {
        "DescribeClusters": {
            "Engine": cluster["Engine"],
            "EngineVersion": cluster["EngineVersion"],
            "NodeType": cluster["NodeType"],
            "NumberOfShards": cluster["NumberOfShards"],
            "TLSEnabled": cluster["TLSEnabled"],
            "ACLName": cluster["ACLName"],
            "SubnetGroupName": cluster["SubnetGroupName"],
            "SecurityGroups": [g["SecurityGroupId"] for g in cluster["SecurityGroups"]],
            "Port": cluster["ClusterEndpoint"]["Port"],
            "ShardSlots": shard["Slots"],
            "NumberOfNodes": shard["NumberOfNodes"],
            "NodePort": node["Endpoint"]["Port"],
            "NodeZoneInNetwork": node["AvailabilityZone"] in net.subnets,
        }
    }
    want = {
        "DescribeClusters": {
            "Engine": "valkey",
            "EngineVersion": _ENGINE_VERSION,
            "NodeType": _NODE_TYPE,
            "NumberOfShards": 1,
            "TLSEnabled": True,
            "ACLName": estate["name"],
            "SubnetGroupName": estate["name"],
            "SecurityGroups": [net.security_group_id],
            "Port": estate["port"],
            "ShardSlots": "0-16383",
            "NumberOfNodes": 1,
            "NodePort": estate["port"],
            "NodeZoneInNetwork": True,
        }
    }
    data_seen, data_want = _data_plane(ctx, fn, estate)
    version = _ENGINE_VERSION
    seen["the engine names itself"] = {
        "server": estate["hello"].get("$server"),
        "mode": estate["hello"].get("$mode"),
        "version matches EngineVersion": str(estate["hello"].get("$version", "$"))[1:].startswith(version),
        "valkey_version matches EngineVersion": estate["info"].get("valkey_version", "").startswith(version),
    }
    want["the engine names itself"] = {
        # MemoryDB's Valkey engine names itself "redis" in the RESP handshake (HELLO's "server"
        # field), unlike community Valkey; INFO's "valkey_version" line is how the actual engine
        # family is visible on the wire.
        "server": "$redis",
        "mode": "$cluster",
        "version matches EngineVersion": True,
        "valkey_version matches EngineVersion": True,
    }
    plane_seen, plane_want = _control_plane(ctx, mdb, estate)
    for part_seen, part_want in ((data_seen, data_want), (plane_seen, plane_want)):
        seen.update(part_seen)
        want.update(part_want)
    bad = {k: {"seen": seen.get(k), "expected": v} for k, v in want.items() if seen.get(k) != v}
    assert not bad, f"{len(bad)} of {len(want)} probes differ: {bad!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
