"""e2e-user-group-replication-group-auth-flow."""
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

CHECK = "e2e-user-group-replication-group-auth-flow"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """ModifyUser rejects the reserved 'default' user (a real user accepts the same call), so with
    a user group holding 'default' and a password user attached, unauthenticated callers keep
    default access, the user's password authenticates, and a wrong password is WRONGPASS."""
    ec = ctx.client("elasticache")
    net = ctx.network()
    probe = _probe_open(ctx, net)
    subnet_ids = net.subnet_ids[:3]
    sg_id = _create_test_security_group(ctx, net.vpc_id, probe, [6379])
    alice_password = secrets.token_urlsafe(18)
    wrong_password = "wrong-" + secrets.token_urlsafe(18)
    subnet_group = ctx.unique_name("sim2real-rbac-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=subnet_group, CacheSubnetGroupDescription="sim2real test", SubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=subnet_group))

    # "default" is a reserved, account-scoped UserId every RBAC user group must contain; it may already
    # exist (CreateUser then raises UserAlreadyExistsFault), so it is adopted when present, created and
    # deleted only when new, and never modified (ModifyUser rejects UserId="default" unconditionally).
    existing_default = ec.describe_users(UserId="default")["Users"] if _user_exists(ec, "default") else []
    if existing_default:
        default_access_string = existing_default[0]["AccessString"]
    else:
        default_access_string = "on ~* +@all"
        ec.create_user(
            UserId="default",
            UserName="default",
            Engine="redis",
            AccessString=default_access_string,
            NoPasswordRequired=True,
        )
        ctx.on_cleanup(lambda: _delete_user_if_present(ctx, "default"))

    alice_id = ctx.unique_name("sim2real-alice-")
    ec.create_user(
        UserId=alice_id,
        UserName=alice_id,
        Engine="redis",
        AccessString="on ~* +@all",
        Passwords=[alice_password],
    )
    ctx.on_cleanup(lambda: _delete_user_if_present(ctx, alice_id))

    # Positive control: the identical ModifyUser(UserId=..., AccessString=...) shape succeeds
    # against a real, non-reserved user, so the account and credentials are otherwise healthy.
    ec.modify_user(UserId=alice_id, AccessString="on ~* +@all")

    # Break exactly one thing: the same call, targeting the reserved "default" identity instead.
    try:
        ec.modify_user(UserId="default", AccessString=default_access_string)
        raise AssertionError("ModifyUser unexpectedly succeeded against the reserved 'default' user")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message!r}"
        assert message == "default user can't be modified.", (
            f"expected the 'default user can't be modified.' message, got {message!r}"
        )

    # Effect-absent: the rejected call left "default" exactly as it was, via an independent read.
    after_default = ec.describe_users(UserId="default")["Users"][0]
    assert after_default["AccessString"] == default_access_string, (
        f"default's AccessString changed despite the rejected ModifyUser: "
        f"{default_access_string!r} -> {after_default['AccessString']!r}"
    )

    group_id = ctx.unique_name("sim2real-usergroup-")
    ec.create_user_group(UserGroupId=group_id, Engine="redis", UserIds=["default", alice_id])
    ctx.on_cleanup(lambda: _delete_user_group_if_present(ctx, group_id))
    _wait_user_group_active(ctx, group_id, timeout_s=180.0)

    rg_id = ctx.unique_name("sim2real-rbac-rg-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real RBAC behavioral test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[sg_id],
        TransitEncryptionEnabled=True,
        UserGroupIds=[group_id],
    )
    ctx.on_cleanup(lambda: _delete_replication_group_if_present(ctx, rg_id))
    rg = _wait_rg_available(ctx, rg_id, timeout_s=1800.0)
    primary = rg["NodeGroups"][0]["PrimaryEndpoint"]
    host, port = primary["Address"], primary["Port"]

    (reply,) = _resp(ctx, probe, host, port, ["PING"])
    assert reply == "+PONG", (
        f"expected unauthenticated PING to succeed: 'default' keeps its permanent "
        f"{default_access_string!r} AccessString (ModifyUser cannot disable it, confirmed "
        f"above) so the endpoint grants unauthenticated callers default access even with "
        f"the custom RBAC user group attached; got {reply!r}"
    )

    payload = ctx.unique_name("payload-")
    reply = _resp(
        ctx, probe, host, port,
        ["AUTH", alice_id, alice_password], ["SET", "sim2real-rbac-key", payload], ["GET", "sim2real-rbac-key"],
    )
    assert reply[0] == "+OK", f"AUTH with the correct password failed: {reply[0]!r}"
    assert reply[1] == "+OK", f"unexpected SET reply after AUTH: {reply[1]!r}"
    assert reply[2] == "$" + payload, f"expected {payload!r}, got {reply[2]!r}"

    (reply,) = _resp(ctx, probe, host, port, ["AUTH", alice_id, wrong_password])
    _probe_release(ctx, probe)
    assert reply.startswith("-WRONGPASS"), f"expected WRONGPASS for a bad password, got {reply!r}"


# ===== helpers =====


def _create_test_security_group(ctx, vpc_id: str, probe: dict, ports: list[int]) -> str:
    """The cache's security group: ``ports`` from the in-VPC probe's group, nothing else."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ec-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elasticache behavioral test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_group(ec2, sg_id))
    perms = [
        {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "UserIdGroupPairs": [{"GroupId": probe["sg"]}]} for p in ports
    ]
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=perms)
    return sg_id


def _wait_rg_available(ctx, rg_id: str, timeout_s: float = 1800.0, interval_s: float = 15.0) -> dict:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_status = "unknown"
    while time.monotonic() < deadline:
        rg = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
        last_status = rg["Status"]
        if last_status == "available":
            return rg
        if last_status == "create-failed":
            raise AssertionError(f"replication group {rg_id} entered create-failed")
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} did not become available within {timeout_s}s (last={last_status})")


def _wait_user_group_active(ctx, group_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_status = "unknown"
    while time.monotonic() < deadline:
        group = ec.describe_user_groups(UserGroupId=group_id)["UserGroups"][0]
        last_status = group["Status"]
        if last_status in ("active", "modifying"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"user group {group_id} did not become active within {timeout_s}s (last={last_status})")


def _user_exists(ec, user_id: str) -> bool:
    try:
        ec.describe_users(UserId=user_id)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("UserNotFound", "UserNotFoundFault"):
            return False
        raise


def _delete_replication_group_if_present(ctx, rg_id: str) -> None:
    # One 900 s bound for the delete and its wait, so every teardown fits the 1800 s budget.
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 900.0
    _delete_until_gone(
        lambda: ec.delete_replication_group(ReplicationGroupId=rg_id),
        "ReplicationGroupNotFound",
        "InvalidReplicationGroupState",
        timeout_s=900.0,
    )
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ReplicationGroupNotFound", "ReplicationGroupNotFoundFault"):
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900s")


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
        time.sleep(2)


def _delete_user_group_if_present(ctx, group_id: str) -> None:
    ec = ctx.client("elasticache")
    _delete_until_gone(
        lambda: ec.delete_user_group(UserGroupId=group_id), "UserGroupNotFound", "InvalidUserGroupState"
    )


def _delete_user_if_present(ctx, user_id: str) -> None:
    ec = ctx.client("elasticache")
    _delete_until_gone(lambda: ec.delete_user(UserId=user_id), "UserNotFound", "InvalidUserState")


def _resp(ctx, probe: dict, host: str, port: int, *commands: list, tls: bool = True) -> list:
    """One RESP session from inside the VPC; its replies, one per command.

    An endpoint that just turned available can refuse its first connections, so a session that
    cannot connect is retried for 60s.
    """
    deadline = time.monotonic() + 60.0
    while True:
        (session,) = _probe_call(ctx, probe, host, port, [{"tls": tls, "commands": [list(c) for c in commands]}])
        if not (session["error"] or "").startswith("connect:") or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert session["error"] is None, (
        f"DATAPLANE_UNIMPLEMENTED: the RESP session to {host}:{port} broke after {session['replies']!r}: "
        f"{session['error']}"
    )
    return session["replies"]


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
