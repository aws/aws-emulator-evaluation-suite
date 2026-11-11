"""efs-mount-without-client-write-is-read-only-and-write-rejected."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "efs-mount-without-client-write-is-read-only-and-write-rejected"
GROUP = "permission-boundary"
SERVICES = ["efs", "lambda"]

MOUNT = "/mnt/data"
MOUNT_TARGET_WAIT_S = 600
_HANDLER = """\
import errno, json, os

MOUNT = "/mnt/data"

def handler(event, context):
    path = os.path.join(MOUNT, event["name"])
    if event["op"] == "write":
        try:
            with open(path, "w") as f:
                f.write(event["body"])
        except OSError as exc:
            return {"written": False, "errno": errno.errorcode.get(exc.errno, str(exc.errno))}
        return {"written": True}
    if not os.path.exists(path):
        return {"exists": False}
    with open(path) as f:
        return {"exists": True, "body": f.read()}
"""

_ENI = {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                                      "ec2:DeleteNetworkInterface",
                                      "ec2:AssignPrivateIpAddresses",
                                      "ec2:UnassignPrivateIpAddresses"], "Resource": "*"}


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role grants elasticfilesystem:ClientMount but not ClientWrite mounts read-only:
    its write fails with EROFS and leaves no file while it still reads a sibling's file; granting
    ClientWrite lets the write through in a new environment.

    Reference: https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html
    """
    net = ctx.network()
    subnet = net.subnet_ids[0]
    efs = ctx.client("efs")
    lam = ctx.client("lambda")

    fs = efs.create_file_system(CreationToken=ctx.unique_name("sim2real-behav-efs-"),
                                PerformanceMode="generalPurpose", Encrypted=False,
                                Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-efs-")},
                                      {"Key": "sim2real", "Value": CHECK}])
    fs_id = fs["FileSystemId"]
    ctx.on_cleanup(_teardown(lambda: efs.delete_file_system(FileSystemId=fs_id),
                             "FileSystemNotFound"))
    _poll(lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
          lambda s: s == "available", timeout_s=300, interval_s=3, what=f"{fs_id} available")
    root = ctx.client("sts").get_caller_identity()["Arn"].split(":")
    efs.put_file_system_policy(FileSystemId=fs_id, Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:{root[1]}:iam::{ctx.account}:root"},
            "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
            "Resource": fs["FileSystemArn"]}]}))
    mt = efs.create_mount_target(FileSystemId=fs_id, SubnetId=subnet,
                                 SecurityGroups=[net.security_group_id])
    ctx.on_cleanup(lambda: _delete_mount_target(efs, fs_id, mt["MountTargetId"]))
    _poll(lambda: efs.describe_mount_targets(MountTargetId=mt["MountTargetId"])["MountTargets"][0][
        "LifeCycleState"], lambda s: s == "available", timeout_s=MOUNT_TARGET_WAIT_S, interval_s=5,
        what=f"mount target of {fs_id} available")
    ap = _access_point(ctx, efs, fs_id, "/shared", uid=1001, mode="755")

    writer_role = _execution_role(ctx, [_ENI, {
        "Effect": "Allow", "Resource": fs["FileSystemArn"],
        "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]}])
    reader_role, reader_role_name = _execution_role(ctx, [_ENI, {
        "Effect": "Allow", "Resource": fs["FileSystemArn"],
        "Action": ["elasticfilesystem:ClientMount"]}], with_name=True)
    vpc = {"SubnetIds": [subnet], "SecurityGroupIds": [net.security_group_id]}
    writer = _vpc_function(ctx, writer_role, vpc, ap)
    reader = _vpc_function(ctx, reader_role, vpc, ap)

    token = ctx.unique_name("payload-")
    wrote = _ok(lam, writer, {"op": "write", "name": "w.txt", "body": token})
    assert wrote == {"written": True}, f"the ClientWrite role's write answered {wrote!r}"
    refused = _ok(lam, reader, {"op": "write", "name": "r.txt", "body": token})
    assert refused == {"written": False, "errno": "EROFS"}, (
        f"a mount without ClientWrite answered the write with {refused!r}")
    assert _ok(lam, writer, {"op": "read", "name": "r.txt"}) == {"exists": False}, (
        "the refused write left a file behind")
    read = _ok(lam, reader, {"op": "read", "name": "w.txt"})
    assert read == {"exists": True, "body": token}, f"the read-only mount reads {read!r}"

    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=reader_role_name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [_ENI, {
                            "Effect": "Allow", "Resource": fs["FileSystemArn"],
                            "Action": ["elasticfilesystem:ClientMount",
                                       "elasticfilesystem:ClientWrite"]}]}))
    _poll(lambda: _fresh_write(lam, reader, token), lambda r: r == {"written": True},
          timeout_s=180, interval_s=10, what="a new environment of the granted role writes")
    # A fresh name: the writer's NFS client may cache its earlier negative lookup of r.txt.
    got = _ok(lam, writer, {"op": "read", "name": "granted.txt"})
    assert got == {"exists": True, "body": token}, f"the granted write is read back as {got!r}"


def _fresh_write(lam, fn, token) -> dict:
    """A write from a NEW environment: changing an environment variable retires the old one."""
    lam.update_function_configuration(FunctionName=fn, Environment={
        "Variables": {"GEN": str(time.monotonic_ns())}})
    _poll(lambda: lam.get_function_configuration(FunctionName=fn),
          lambda c: c.get("LastUpdateStatus") == "Successful", timeout_s=300, interval_s=3,
          what=f"{fn} configuration update applies")
    return _ok(lam, fn, {"op": "write", "name": "granted.txt", "body": token})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _delete_mount_target(efs, fs_id, mt_id) -> None:
    """Delete the mount target and wait until the file system lists none, so it can delete."""
    _teardown(lambda: efs.delete_mount_target(MountTargetId=mt_id), "MountTargetNotFound")()
    _poll(lambda: efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"],
          lambda mts: mts == [], timeout_s=300, interval_s=5, what=f"{fs_id} has no mount targets")


def _access_point(ctx, efs, fs_id, root, *, uid, mode) -> dict:
    kwargs = {"ClientToken": ctx.unique_name("sim2real-ap-"), "FileSystemId": fs_id,
              "PosixUser": {"Uid": uid, "Gid": uid},
              "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if root:
        kwargs["RootDirectory"] = {"Path": root, "CreationInfo": {
            "OwnerUid": uid, "OwnerGid": uid, "Permissions": mode}}
    ap = efs.create_access_point(**kwargs)
    ap_id = ap["AccessPointId"]
    ctx.on_cleanup(_teardown(lambda: efs.delete_access_point(AccessPointId=ap_id),
                             "AccessPointNotFound"))
    _poll(lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["LifeCycleState"],
          lambda s: s == "available", timeout_s=120, interval_s=2, what=f"{ap_id} available")
    return ap


def _execution_role(ctx, statements, *, with_name=False):
    """A Lambda execution role holding exactly ``statements`` and no logs: grant."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
        "NoSuchEntity"))
    return (arn, name) if with_name else arn


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _vpc_function(ctx, role_arn, vpc, ap) -> str:
    """A python3.12 function in ``vpc`` mounting access point ``ap`` at MOUNT, Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-efsfn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(_HANDLER)}, "Timeout": 30,
              "MemorySize": 256, "VpcConfig": vpc, "Tags": {"sim2real": CHECK},
              "FileSystemConfigs": [{"Arn": ap["AccessPointArn"], "LocalMountPath": MOUNT}]}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and (
                    "cannot be assumed" in err.get("Message", "")
                    or "does not have permissions" in err.get("Message", "")):
                return None
            raise

    _poll(create, lambda r: r is not None, timeout_s=120, interval_s=5,
          what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State") in ("Active", "Failed"), timeout_s=600, interval_s=5,
                 what=f"function {name} leaves Pending")
    assert conf["State"] == "Active", f"{name}: {conf['State']!r} {conf.get('StateReason')!r}"
    return name


def _ok(lam, fn, event) -> dict:
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(event).encode())
    raw = resp["Payload"].read()
    assert resp.get("FunctionError") is None, (
        f"{event['op']} on {fn} failed: {resp.get('FunctionError')!r} {raw[:400]!r}")
    return json.loads(raw)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
