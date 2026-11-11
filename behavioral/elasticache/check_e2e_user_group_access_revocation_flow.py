"""e2e-user-group-access-revocation-flow."""
from __future__ import annotations

import io
import json
import secrets
import time
import zipfile
from pathlib import Path

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-user-group-access-revocation-flow"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """A user in a user group attached to a replication group authenticates over Redis; once removed from the
    group the running engine refuses its AUTH, and once added back the identical AUTH succeeds again."""
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    net = ctx.network()
    probe = _probe_open(ctx, net)

    user_id = ctx.unique_name("sim2real-user-")
    group_id = ctx.unique_name("sim2real-ugrp-")
    rg_id = ctx.unique_name("sim2real-rg-")
    password = secrets.token_urlsafe(24)
    subnet_group_name = _create_subnet_group(ctx, ec, net)
    sg_id = _probe_security_group(ctx, ec2, net, probe, 6379)

    ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        Passwords=[password],
        AccessString="on ~* +@all",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(lambda: ec.delete_user(UserId=user_id), "UserNotFound", "InvalidUserState"))

    ec.create_user_group(
        UserGroupId=group_id,
        Engine="redis",
        UserIds=["default", user_id],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _delete_until_gone(
            lambda: ec.delete_user_group(UserGroupId=group_id), "UserGroupNotFound", "InvalidUserGroupState"
        )
    )

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real user-group revocation test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        TransitEncryptionEnabled=True,
        CacheSubnetGroupName=subnet_group_name,
        SecurityGroupIds=[sg_id],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, rg_id))

    rg = _poll_until(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0],
        lambda r: r["Status"] == "available",
        timeout_s=900,
        interval_s=20,
    )
    assert rg["Status"] == "available", f"replication group {rg_id} not available after create: {rg['Status']!r}"

    ec.modify_replication_group(
        ReplicationGroupId=rg_id, UserGroupIdsToAdd=[group_id], ApplyImmediately=True
    )
    rg = _poll_until(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0],
        lambda r: r["Status"] == "available" and group_id in r.get("UserGroupIds", []),
        timeout_s=600,
        interval_s=20,
    )
    assert group_id in rg["UserGroupIds"], (
        f"expected {group_id} attached to {rg_id}, got UserGroupIds={rg['UserGroupIds']!r}"
    )

    endpoint = rg["NodeGroups"][0]["PrimaryEndpoint"]
    host, port = endpoint["Address"], endpoint["Port"]

    def ping(username, password):
        return _redis_ping(ctx, probe, host, port, username, password)

    # Positive control: the user is still in the group -> real authentication succeeds.
    _ping_expect_ok(ping(user_id, password))

    # Break exactly one thing: remove the user from the group that grants access.
    ec.modify_user_group(UserGroupId=group_id, UserIdsToRemove=[user_id])
    _poll_until(
        lambda: ec.describe_user_groups(UserGroupId=group_id)["UserGroups"][0],
        # The group turns modifying, and back to active once the engine applies the change.
        lambda g: user_id not in g.get("UserIds", []) and g.get("Status") == "active",
        timeout_s=600,
        interval_s=15,
    )
    _poll_until(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0],
        lambda r: r["Status"] == "available",
        timeout_s=600,
        interval_s=15,
    )

    # The effect must be observable on the real data plane: the removed user can no longer
    # authenticate, even though it could moments ago (positive control above).
    _ping_expect_auth_rejected(ping(user_id, password))

    # Restore: add the user back to the group that grants access.
    ec.modify_user_group(UserGroupId=group_id, UserIdsToAdd=[user_id])
    rg = _poll_until(
        lambda: ec.describe_user_groups(UserGroupId=group_id)["UserGroups"][0],
        lambda g: user_id in g.get("UserIds", []) and g.get("Status") == "active",
        timeout_s=600,
        interval_s=15,
    )
    assert user_id in rg["UserIds"], f"expected {user_id} restored to {group_id}, got UserIds={rg['UserIds']!r}"
    _poll_until(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0],
        lambda r: r["Status"] == "available",
        timeout_s=600,
        interval_s=15,
    )

    # The identical call that was just rejected must now succeed again.
    _ping_expect_ok(ping(user_id, password))
    _probe_release(ctx, probe)


def _poll_until(probe, predicate, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_subnet_group(ctx, ec, net) -> str:
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=net.subnet_ids[:3],
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
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_group(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": probe["sg"]}]}
        ],
    )
    return sg_id


def _delete_until_gone(fn, gone_code: str, busy_code: str, timeout_s: float = 600.0) -> None:
    """``fn()`` until it succeeds or reports the resource gone; a busy resource is retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (gone_code, gone_code + "Fault"):
                return
            if code not in (busy_code, busy_code + "Fault") or time.monotonic() >= deadline:
                raise
        time.sleep(15)


def _delete_replication_group(ec, rg_id: str) -> None:
    try:
        rg = _poll_until(
            lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][
                0
            ],
            lambda r: r["Status"] == "available",
            timeout_s=600,
            interval_s=20,
        )
        assert rg["Status"] == "available", f"replication group {rg_id} not available before delete: {rg['Status']!r}"
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault", "ReplicationGroupNotFound"):
            return
        raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault", "ReplicationGroupNotFound"):
                return
            raise
        time.sleep(20)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900s")


def _redis_ping(ctx, probe: dict, host, port, username, password):
    """Return (ok, detail) for a TLS PING from inside the VPC, after AUTH when ``password`` is set.

    ok is True only on an accepted AUTH and a genuine PONG; detail carries the first error reply.
    The group holds the default user, so a PING after a refused AUTH still answers, as that user. A freshly-available
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
    return not errors and session["replies"][-1:] == ["+PONG"], (errors[0] if errors else None)


def _ping_expect_ok(result) -> None:
    ok, detail = result
    if not ok:
        raise AssertionError(f"expected PING to succeed but it was rejected: {detail}")


def _ping_expect_auth_rejected(result) -> None:
    ok, _detail = result
    if ok:
        raise AssertionError(
            "expected the removed user's authentication to be rejected but PING succeeded"
        )


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
