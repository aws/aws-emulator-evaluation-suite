"""auth-token-special-characters-preserved."""
from __future__ import annotations

import io
import json
import secrets
import string
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-token-special-characters-preserved"
GROUP = "server-side"
SERVICES = ["elasticache"]

# ElastiCache AUTH tokens allow only these non-alphanumeric characters: !&#$^<>-
_SPECIALS = "!&#$^<>-"
_AUTH_REFUSED = ("-WRONGPASS", "-NOAUTH")


def _special_token() -> str:
    """A fresh 24-character token holding every allowed special character, in random order."""
    chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(16)] + list(_SPECIALS)
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """An AuthToken using the special characters !&#$^<>- is accepted at CreateReplicationGroup and
    authenticates over Redis; after a ROTATE then SET rotation to a second such token, the new token
    authenticates and the old one is refused by AUTH."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    net = ctx.network()
    probe = _probe_open(ctx, net)
    token_a, token_b = _special_token(), _special_token()
    subnet_group = _create_cache_subnet_group(ctx, ec, net.subnet_ids[:2])
    sg_id = _probe_security_group(ctx, ec2, net, probe, 6379)

    rg_id = ctx.unique_name("sim2real-authspecial-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real special-char auth token check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        TransitEncryptionEnabled=True,
        AutomaticFailoverEnabled=False,
        AuthToken=token_a,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[sg_id],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, rg_id))
    _wait_for_status(ec, rg_id, {"available"}, timeout_s=1200)
    host, port = _primary_endpoint(ec, rg_id)

    def _ping(password: str):
        return _redis_ping(ctx, probe, host, port, None, password)

    assert _ping(token_a)[0] is True, "special-character auth token rejected at creation"

    # Two-phase rotation to a second special-character-laden token.
    ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        AuthToken=token_b,
        AuthTokenUpdateStrategy="ROTATE",
        ApplyImmediately=True,
    )
    _wait_for_status(ec, rg_id, {"available"}, timeout_s=600)
    ec.modify_replication_group(
        ReplicationGroupId=rg_id,
        AuthToken=token_b,
        AuthTokenUpdateStrategy="SET",
        ApplyImmediately=True,
    )
    _wait_for_status(ec, rg_id, {"available"}, timeout_s=600)

    assert _ping(token_b)[0] is True, "rotated special-character auth token failed to authenticate"

    ok, detail = _ping(token_a)
    _probe_release(ctx, probe)
    assert not ok, "old auth token still authenticated after the SET rotation completed"
    assert str(detail).startswith(_AUTH_REFUSED), f"old auth token refused for a reason other than auth: {detail!r}"


def _create_cache_subnet_group(ctx, ec: Any, subnet_ids: list) -> str:
    name = ctx.unique_name("sim2real-authspecial-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real special-char auth token check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


def _probe_security_group(ctx, ec2, net, probe: dict, port: int) -> str:
    """The cache's security group: ``port`` from the in-VPC probe's group, nothing else."""
    name = ctx.unique_name("sim2real-ec-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elasticache behavioral check",
        VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_group(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": probe["sg"]}]}
        ],
    )
    return sg_id


def _primary_endpoint(ec: Any, rg_id: str) -> tuple[str, int]:
    resp = ec.describe_replication_groups(ReplicationGroupId=rg_id)
    node_group = resp["ReplicationGroups"][0]["NodeGroups"][0]
    ep = node_group["PrimaryEndpoint"]
    return ep["Address"], ep["Port"]


def _wait_for_status(ec: Any, rg_id: str, targets: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_replication_groups(ReplicationGroupId=rg_id)
        last = resp["ReplicationGroups"][0]["Status"]
        if last in targets:
            return last
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached {targets}; last={last}")


def _delete_replication_group(ec: Any, rg_id: str) -> None:
    deadline = time.monotonic() + 900
    while True:  # a group still modifying refuses the delete; retry until it settles
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            break
        except ec.exceptions.ReplicationGroupNotFoundFault:
            return
        except ec.exceptions.InvalidReplicationGroupStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(20)
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ec.exceptions.ReplicationGroupNotFoundFault:
            return
        time.sleep(20)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900s")


def _redis_ping(ctx, probe: dict, host, port, username, password):
    """Return (ok, detail) for a TLS PING from inside the VPC, after AUTH when ``password`` is set.

    ok is True only on a genuine PONG; detail carries the first error reply. A freshly-available
    replication group can refuse connections for a few seconds after DescribeReplicationGroups
    reports "available", so a session that cannot connect is retried for 60s; one that still
    cannot raises AssertionError.
    """
    auth = ([["AUTH", username, password]] if username else [["AUTH", password]]) if password else []
    deadline = time.monotonic() + 60.0
    while True:
        (session,) = _probe_call(ctx, probe, host, port, [{"tls": True, "commands": auth + [["PING"]]}])
        if not (session["error"] or "").startswith("connect:") or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    errors = [r for r in session["replies"] if isinstance(r, str) and r.startswith("-")]
    if session["error"] is not None and not errors:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: ElastiCache endpoint {host}:{port} not reachable from inside "
            f"its VPC: {session['error']}"
        )
    return session["replies"][-1:] == ["+PONG"], (errors[0] if errors else None)


def _delete_group(ec2, sg_id: str, timeout_s: float = 600.0) -> None:
    """Delete the cache's group, retrying while the deleted cache's interfaces still hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(15.0)

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
