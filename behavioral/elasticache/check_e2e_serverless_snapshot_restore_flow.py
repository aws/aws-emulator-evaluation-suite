"""e2e-serverless-snapshot-restore-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-serverless-snapshot-restore-flow"
GROUP = "e2e"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """Write data into a serverless cache, snapshot it, delete the cache, restore a new
    cache from the snapshot, and verify the original data is present."""
    ec = ctx.client("elasticache")
    net = ctx.network()
    probe = _probe_open(ctx, net)
    subnet_ids = net.subnet_ids[:2]
    sg_id = _probe_security_group(ctx, net.vpc_id, probe, 6379)

    cache1_name = ctx.unique_name("sim2real-ec-slc1-")
    ec.create_serverless_cache(
        ServerlessCacheName=cache1_name, Engine="redis", SecurityGroupIds=[sg_id], SubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_if_present(ctx, cache1_name))
    cache1 = _wait_serverless_cache_available(ctx, cache1_name)

    host, port = cache1["Endpoint"]["Address"], cache1["Endpoint"]["Port"]
    key = ctx.unique_name("sim2real-serverless-key-")
    replies = _tls_session(ctx, probe, host, port, ["SET", key, "serverless-original-value"], ["GET", key])
    assert replies == ["+OK", "$serverless-original-value"], f"unexpected SET/GET replies: {replies!r}"

    snapshot_name = ctx.unique_name("sim2real-ec-slc-snap-")
    snapshot = ec.create_serverless_cache_snapshot(
        ServerlessCacheSnapshotName=snapshot_name, ServerlessCacheName=cache1_name
    )["ServerlessCacheSnapshot"]
    ctx.on_cleanup(lambda: _delete_snapshot_if_present(ctx, snapshot_name))
    snapshot = _wait_snapshot_available(ctx, snapshot_name)
    snapshot_arn = snapshot["ARN"]

    _delete_serverless_cache_if_present(ctx, cache1_name)

    cache2_name = ctx.unique_name("sim2real-ec-slc2-")
    ec.create_serverless_cache(
        ServerlessCacheName=cache2_name,
        Engine="redis",
        SecurityGroupIds=[sg_id],
        SubnetIds=subnet_ids,
        SnapshotArnsToRestore=[snapshot_arn],
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_if_present(ctx, cache2_name))
    # A restore loads the snapshot before the cache turns available, which takes longer.
    cache2 = _wait_serverless_cache_available(ctx, cache2_name, timeout_s=1800.0)

    host2, port2 = cache2["Endpoint"]["Address"], cache2["Endpoint"]["Port"]
    (restored_value,) = _tls_session(ctx, probe, host2, port2, ["GET", key])
    _probe_release(ctx, probe)
    assert restored_value == "$serverless-original-value", (
        f"restored serverless cache is missing pre-snapshot data, got {restored_value!r}"
    )


def _probe_security_group(ctx: Any, vpc_id: str, probe: dict, port: int) -> str:
    """The cache's security group: ``port`` from the in-VPC probe's group, nothing else."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ec-sg-")
    sg_id = ec2.create_security_group(GroupName=name, Description="sim2real elasticache behavioral", VpcId=vpc_id)[
        "GroupId"
    ]
    ctx.on_cleanup(lambda: _delete_group(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "UserIdGroupPairs": [{"GroupId": probe["sg"]}]}],
    )
    return sg_id


def _delete_group(ec2, sg_id: str, timeout_s: float = 600.0) -> None:
    """The serverless caches' endpoint interfaces leave the group after the caches are gone.

    The check created the group and only this teardown deletes it, so a missing group is reported,
    not taken as success.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(15.0)


def _wait_serverless_cache_available(ctx: Any, name: str, timeout_s: float = 900.0) -> dict:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        caches = ec.describe_serverless_caches(ServerlessCacheName=name)["ServerlessCaches"]
        last = caches[0] if caches else None
        if last and last["Status"] == "available":
            return last
        time.sleep(2)
    raise AssertionError(f"serverless cache {name} never reached available, last={last}")


def _wait_snapshot_available(ctx: Any, name: str, timeout_s: float = 600.0) -> dict:
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        snaps = ec.describe_serverless_cache_snapshots(ServerlessCacheSnapshotName=name)["ServerlessCacheSnapshots"]
        last = snaps[0] if snaps else None
        if last and last["Status"] == "available":
            return last
        time.sleep(2)
    raise AssertionError(f"serverless cache snapshot {name} never reached available, last={last}")


def _delete_serverless_cache_if_present(ctx: Any, name: str) -> None:
    """Delete the cache, retrying while it is still creating or busy, and wait until it is gone."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 1500.0
    while True:
        try:
            ec.delete_serverless_cache(ServerlessCacheName=name)
            break
        except ec.exceptions.ServerlessCacheNotFoundFault:
            return
        except ec.exceptions.InvalidServerlessCacheStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(20)
    while time.monotonic() < deadline:
        try:
            ec.describe_serverless_caches(ServerlessCacheName=name)
        except ec.exceptions.ServerlessCacheNotFoundFault:
            return
        time.sleep(15)
    raise AssertionError(f"serverless cache {name} was not deleted within 1500s")


def _delete_snapshot_if_present(ctx: Any, name: str) -> None:
    """Delete the snapshot, retrying while a restore from it still holds it."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 600.0
    while True:
        try:
            ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=name)
            return
        except ec.exceptions.ServerlessCacheSnapshotNotFoundFault:
            return
        except ec.exceptions.InvalidServerlessCacheSnapshotStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(20)


def _tls_session(ctx: Any, probe: dict, host: str, port: int, *commands: list) -> list:
    """One TLS RESP session from inside the VPC; its replies, one per command.

    A cache that just turned available can refuse its first connections, so a session that
    cannot connect is retried for 180s.
    """
    deadline = time.monotonic() + 180.0
    while True:
        (session,) = _probe_call(ctx, probe, host, port, [{"tls": True, "commands": [list(c) for c in commands]}])
        if not (session["error"] or "").startswith("connect:") or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert session["error"] is None, (
        f"DATAPLANE_UNIMPLEMENTED: the TLS RESP session to {host}:{port} broke after {session['replies']!r}: "
        f"{session['error']}"
    )
    return session["replies"]


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
