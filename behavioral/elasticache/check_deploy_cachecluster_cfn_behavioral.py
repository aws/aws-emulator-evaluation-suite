"""deploy-cachecluster-cfn-behavioral."""
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

CHECK = "deploy-cachecluster-cfn-behavioral"
GROUP = "deploy"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "dp:native", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ElastiCache::CacheCluster accepts real SET/GET
    traffic over the Redis wire protocol, not just a CREATE_COMPLETE stack status."""
    net = ctx.network()
    probe = _probe_open(ctx, net)

    template = json.dumps(
        {
            "Resources": {
                "CacheSG": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real elasticache behavioral cache cluster",
                        "VpcId": net.vpc_id,
                        "SecurityGroupIngress": [
                            {"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379, "SourceSecurityGroupId": probe["sg"]}
                        ],
                    },
                },
                "SubnetGroup": {
                    "Type": "AWS::ElastiCache::SubnetGroup",
                    "Properties": {
                        "Description": "sim2real behavioral subnet group",
                        "SubnetIds": net.subnet_ids[:2],
                    },
                },
                "Cluster": {
                    "Type": "AWS::ElastiCache::CacheCluster",
                    "Properties": {
                        "Engine": "redis",
                        "CacheNodeType": "cache.t3.micro",
                        "NumCacheNodes": 1,
                        "VpcSecurityGroupIds": [{"Fn::GetAtt": ["CacheSG", "GroupId"]}],
                        "CacheSubnetGroupName": {"Ref": "SubnetGroup"},
                    },
                },
            },
            "Outputs": {
                "Address": {"Value": {"Fn::GetAtt": ["Cluster", "RedisEndpoint.Address"]}},
                "Port": {"Value": {"Fn::GetAtt": ["Cluster", "RedisEndpoint.Port"]}},
            },
        }
    )

    stack_name = _deploy_cfn(ctx, template)
    cfn = ctx.client("cloudformation")
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    host, port = outputs["Address"], int(outputs["Port"])

    key = ctx.unique_name("sim2real-cfn-key-")
    (session,) = _probe_call(
        ctx, probe, host, port, [{"tls": False, "commands": [["SET", key, "cfn-deployed-value"], ["GET", key]]}]
    )
    _probe_release(ctx, probe)
    assert session["error"] is None, (
        f"DATAPLANE_UNIMPLEMENTED: the RESP session to {host}:{port} broke after {session['replies']!r}: "
        f"{session['error']}"
    )
    assert session["replies"] == ["+OK", "$cfn-deployed-value"], (
        f"expected SET +OK and the round-tripped value, got {session['replies']!r}"
    )


def _deploy_cfn(ctx: Any, template_body: str) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ec-cachecluster-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": stack_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    return stack_name


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})


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
