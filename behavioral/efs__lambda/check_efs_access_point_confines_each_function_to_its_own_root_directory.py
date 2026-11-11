"""efs-access-point-confines-each-function-to-its-own-root-directory."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "efs-access-point-confines-each-function-to-its-own-root-directory"
GROUP = "data-plane"
SERVICES = ["efs", "lambda"]

MOUNT = "/mnt/data"
MOUNT_TARGET_WAIT_S = 600
_HANDLER = """\
import json, os

MOUNT = "/mnt/data"

def handler(event, context):
    op = event["op"]
    if op == "write":
        with open(os.path.join(MOUNT, event["name"]), "w") as f:
            f.write(event["body"])
    if op == "read":
        path = os.path.join(MOUNT, event["path"])
        if not os.path.exists(path):
            return {"exists": False}
        st = os.stat(path)
        with open(path) as f:
            return {"exists": True, "body": f.read(), "uid": st.st_uid, "gid": st.st_gid}
    if op == "stat":
        st = os.stat(os.path.join(MOUNT, event["path"]))
        return {"uid": st.st_uid, "gid": st.st_gid, "mode": st.st_mode & 0o7777}
    return {"listing": sorted(os.listdir(MOUNT))}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Functions on two access points of one EFS file system each see only their own root: A's file
    is absent from B and unreachable via ../, while a "/" access point sees both roots, A's file
    owned by A's POSIX user, and each root created with its CreationInfo owner and mode.

    Reference: https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html
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
    mt = efs.create_mount_target(FileSystemId=fs_id, SubnetId=subnet,
                                 SecurityGroups=[net.security_group_id])
    ctx.on_cleanup(lambda: _delete_mount_target(efs, fs_id, mt["MountTargetId"]))
    _poll(lambda: efs.describe_mount_targets(MountTargetId=mt["MountTargetId"])["MountTargets"][0][
        "LifeCycleState"], lambda s: s == "available", timeout_s=MOUNT_TARGET_WAIT_S, interval_s=5,
        what=f"mount target of {fs_id} available")

    ap_a = _access_point(ctx, efs, fs_id, "/sim2real-a", uid=1001, mode="750")
    ap_b = _access_point(ctx, efs, fs_id, "/sim2real-b", uid=1002, mode="700")
    ap_root = _access_point(ctx, efs, fs_id, None, uid=0, mode=None)

    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface",
                                       "ec2:DescribeNetworkInterfaces",
                                       "ec2:DeleteNetworkInterface",
                                       "ec2:AssignPrivateIpAddresses",
                                       "ec2:UnassignPrivateIpAddresses"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["elasticfilesystem:ClientMount",
                                       "elasticfilesystem:ClientWrite",
                                       "elasticfilesystem:ClientRootAccess"],
         "Resource": fs["FileSystemArn"]}])
    vpc = {"SubnetIds": [subnet], "SecurityGroupIds": [net.security_group_id]}
    fn_a = _vpc_function(ctx, role, vpc, ap_a)
    fn_b = _vpc_function(ctx, role, vpc, ap_b)
    fn_root = _vpc_function(ctx, role, vpc, ap_root)

    token = ctx.unique_name("payload-")
    _ok(lam, fn_a, {"op": "write", "name": "a.txt", "body": token})
    again = _ok(lam, fn_a, {"op": "read", "path": "a.txt"})
    assert again == {"exists": True, "body": token, "uid": 1001, "gid": 1001}, (
        f"A's next invocation reads back {again!r}")

    b_view = _ok(lam, fn_b, {"op": "list"})
    assert b_view == {"listing": []}, f"B's mount shows {b_view!r}"
    escaped = _ok(lam, fn_b, {"op": "read", "path": "../sim2real-a/a.txt"})
    assert escaped == {"exists": False}, f"B reached A's file by a relative path: {escaped!r}"

    root_view = _ok(lam, fn_root, {"op": "list"})
    assert root_view == {"listing": ["sim2real-a", "sim2real-b"]}, (
        f"the root access point shows {root_view!r}")
    via_root = _ok(lam, fn_root, {"op": "read", "path": "sim2real-a/a.txt"})
    assert via_root == {"exists": True, "body": token, "uid": 1001, "gid": 1001}, (
        f"A's file seen from the root access point: {via_root!r}")
    for path, uid, mode in (("sim2real-a", 1001, 0o750), ("sim2real-b", 1002, 0o700)):
        st = _ok(lam, fn_root, {"op": "stat", "path": path})
        assert st == {"uid": uid, "gid": uid, "mode": mode}, f"{path} was created as {st!r}"


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


def _execution_role(ctx, statements) -> str:
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
    return arn


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
