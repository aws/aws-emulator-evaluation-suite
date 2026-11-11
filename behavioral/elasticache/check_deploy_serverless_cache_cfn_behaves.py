"""deploy-serverless-cache-cfn-behaves."""
from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-serverless-cache-cfn-behaves"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """A CFN-provisioned ServerlessCache becomes AVAILABLE and serves a real TLS Redis round-trip;
    tearing the stack down actually removes the resource (404 on describe afterward)."""
    net = ctx.network()
    probe = _probe_open(ctx, net)
    subnet_ids = net.subnet_ids[:2]
    sg_id = _create_test_security_group(ctx, net.vpc_id, probe, [6379])

    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")
    stack_name = ctx.unique_name("sim2real-ec-sc-stack-")
    cache_name = ctx.unique_name("sim2real-sc-")

    template = json.dumps(
        {
            "Resources": {
                "ServerlessCache": {
                    "Type": "AWS::ElastiCache::ServerlessCache",
                    "Properties": {
                        "ServerlessCacheName": cache_name,
                        "Engine": "redis",
                        "SubnetIds": subnet_ids,
                        "SecurityGroupIds": [sg_id],
                    },
                }
            }
        }
    )
    stack_deleted = {"done": False}

    def _cleanup_stack() -> None:
        if not stack_deleted["done"]:
            _delete_stack(ctx, stack_name)
            stack_deleted["done"] = True

    cfn.create_stack(StackName=stack_name, TemplateBody=template, OnFailure="DELETE")

    ctx.on_cleanup(_cleanup_stack)
    status = _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=1200.0)
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"

    desc = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"][0]
    # AWS returns the lowercase wire value ("available"), not the uppercase enum name ("AVAILABLE")
    # the API reference documents.
    assert desc["Status"] == "available", desc["Status"]
    endpoint = desc["Endpoint"]
    host, port = endpoint["Address"], endpoint["Port"]

    # A just-AVAILABLE serverless endpoint can still time out new connections for a while: retry
    # only a failed connect, to an AWS-plausible deadline capped by the run's remaining time.
    left = ctx.time_left()
    connect_deadline = time.monotonic() + (_CONNECT_WAIT_S if left is None else min(_CONNECT_WAIT_S, left - 60.0))
    while True:
        (session,) = _probe_call(ctx, probe, host, port, [{"tls": True, "commands": [["PING"]]}])
        if not str(session["error"] or "").startswith("connect:") or time.monotonic() >= connect_deadline:
            break
        time.sleep(2)
    _probe_release(ctx, probe)
    assert session["error"] is None, (
        f"DATAPLANE_UNIMPLEMENTED: the TLS RESP session to {host}:{port} broke after {session['replies']!r}: "
        f"{session['error']}"
    )
    reply = session["replies"][0]
    assert reply == "+PONG", f"unexpected PING reply from serverless cache: {reply!r}"

    _cleanup_stack()
    code, message = _error(lambda: ec.describe_serverless_caches(ServerlessCacheName=cache_name))
    assert code == "ServerlessCacheNotFoundFault", code
    assert message == f"Serverless cache with name {cache_name} not found.", (
        f"expected the DescribeServerlessCaches not-found message, got {message!r}"
    )


_CONNECT_WAIT_S = 300.0


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


def _wait_stack_status(
    ctx, stack_name: str, target_statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 15.0
) -> str:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError" and "DELETE_COMPLETE" in target_statuses:
                return "DELETE_COMPLETE"
            raise
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError:
        pass
    _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"}, timeout_s=900.0)


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("the call unexpectedly succeeded")


def _delete_group(ec2, sg_id: str, timeout_s: float = 600.0) -> None:
    """The serverless cache's endpoint interfaces leave the group after the stack is gone.

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
