"""filesystemconfigs-mount-path-outside-mnt-and-missing-vpc-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filesystemconfigs-mount-path-outside-mnt-and-missing-vpc-rejected"
GROUP = "configuration-validation"
SERVICES = ["efs", "lambda"]

MOUNT = "/mnt/data"
MOUNT_TARGET_WAIT_S = 600
_HANDLER = """\
def handler(event, context):
    return {"ok": True}
"""

_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreateFunction rejects a FileSystemConfigs LocalMountPath outside /mnt/ and rejects an
    otherwise-valid access point reference when the function has no VpcConfig, creating nothing
    either time, while the same configuration with a conforming path and a VpcConfig succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem-efs.html
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
    _poll(ctx, lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
          lambda s: s == "available", timeout_s=300, what=f"{fs_id} available")
    mt = efs.create_mount_target(FileSystemId=fs_id, SubnetId=subnet,
                                 SecurityGroups=[net.security_group_id])
    ctx.on_cleanup(lambda: _delete_mount_target(ctx, efs, fs_id, mt["MountTargetId"]))
    _poll(ctx, lambda: efs.describe_mount_targets(MountTargetId=mt["MountTargetId"])["MountTargets"][0][
        "LifeCycleState"], lambda s: s == "available", timeout_s=MOUNT_TARGET_WAIT_S,
        what=f"mount target of {fs_id} available")
    ap = _access_point(ctx, efs, fs_id, "/sim2real", uid=1001, mode="750")
    ap_arn = ap["AccessPointArn"]

    role_arn = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface",
                                       "ec2:DescribeNetworkInterfaces",
                                       "ec2:DeleteNetworkInterface",
                                       "ec2:AssignPrivateIpAddresses",
                                       "ec2:UnassignPrivateIpAddresses"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["elasticfilesystem:ClientMount",
                                       "elasticfilesystem:ClientWrite"],
         "Resource": fs["FileSystemArn"]}])
    vpc = {"SubnetIds": [subnet], "SecurityGroupIds": [net.security_group_id]}

    # ---- 1. A LocalMountPath outside /mnt/ is rejected by the model's own pattern, whether or
    # not VpcConfig is present, and creates nothing.
    bad_path = "/data/sim2real"
    bad_name = ctx.unique_name("sim2real-behav-efsbad1-")
    code = _error_code(ctx, lambda: lam.create_function(
        FunctionName=bad_name, Runtime="python3.13", Handler="index.handler", Role=role_arn,
        Code={"ZipFile": _zip(_HANDLER)}, Timeout=30, MemorySize=256, VpcConfig=vpc,
        FileSystemConfigs=[{"Arn": ap_arn, "LocalMountPath": bad_path}], Tags={"sim2real": CHECK},
    ), tolerate=_ROLE_NOT_READY, on_success=lambda _r: ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=bad_name), "ResourceNotFoundException")))
    assert code[0] == "ValidationException", f"bad LocalMountPath rejected with {code!r}"
    assert code[1] == (
        f"1 validation error detected: Value '{bad_path}' at "
        "'fileSystemConfigs.1.member.localMountPath' failed to satisfy constraint: Member must "
        "satisfy regular expression pattern: /mnt/[a-zA-Z0-9-_.]+"
    ), f"unexpected message for a LocalMountPath outside /mnt/: {code[1]!r}"
    _assert_no_function(ctx, lam, bad_name)

    # ---- 2. The same access point, a conforming path, but no VpcConfig: rejected because the
    # function is not in a VPC, and creates nothing.
    novpc_name = ctx.unique_name("sim2real-behav-efsbad2-")
    code = _error_code(ctx, lambda: lam.create_function(
        FunctionName=novpc_name, Runtime="python3.13", Handler="index.handler", Role=role_arn,
        Code={"ZipFile": _zip(_HANDLER)}, Timeout=30, MemorySize=256,
        FileSystemConfigs=[{"Arn": ap_arn, "LocalMountPath": MOUNT}], Tags={"sim2real": CHECK},
    ), tolerate=_ROLE_NOT_READY, on_success=lambda _r: ctx.on_cleanup(_teardown(
        lambda: lam.delete_function(FunctionName=novpc_name), "ResourceNotFoundException")))
    assert code[0] == "InvalidParameterValueException", f"missing VpcConfig rejected with {code!r}"
    assert code[1] == (
        f"Function must be configured to execute in a VPC to reference access point {ap_arn}. "
        "Please update the function configuration to include VPC subnets and security groups."
    ), f"unexpected message for FileSystemConfigs with no VpcConfig: {code[1]!r}"
    _assert_no_function(ctx, lam, novpc_name)

    # ---- 3. Positive control: the same access point, a conforming path, and a VpcConfig succeeds.
    good_name = _create_function_retrying(ctx, lam, dict(
        FunctionName=ctx.unique_name("sim2real-behav-efsok-"), Runtime="python3.13",
        Handler="index.handler", Role=role_arn, Code={"ZipFile": _zip(_HANDLER)}, Timeout=30,
        MemorySize=256, VpcConfig=vpc, Tags={"sim2real": CHECK},
        FileSystemConfigs=[{"Arn": ap_arn, "LocalMountPath": MOUNT}],
    ))
    conf = lam.get_function_configuration(FunctionName=good_name)
    assert conf["FileSystemConfigs"] == [{"Arn": ap_arn, "LocalMountPath": MOUNT}], (
        f"the accepted function's FileSystemConfigs echoed {conf.get('FileSystemConfigs')!r}"
    )


def _assert_no_function(ctx, lam, name: str) -> None:
    arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    try:
        lam.get_function(FunctionName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ResourceNotFoundException", (
            f"GetFunction({name}) after a rejected CreateFunction raised {err!r}"
        )
        assert err["Message"] == f"Function not found: {arn}", (
            f"GetFunction({name}) after a rejected CreateFunction said {err['Message']!r}"
        )
        return
    raise AssertionError(f"CreateFunction({name}) was rejected, but GetFunction found it anyway")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code(ctx, fn, *, tolerate: tuple[str, ...] = (), on_success=None,
                 timeout_s: float = 90.0) -> tuple[str, str]:
    """``(Error.Code, Error.Message)`` of ``fn()``; retries only a role-propagation refusal.

    If ``fn()`` unexpectedly succeeds, ``on_success(result)`` runs before this raises, so a
    surprise acceptance still gets a cleanup registered rather than leaking.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if any(t in err.get("Message", "") for t in tolerate) and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if _budget_spent(ctx):
                raise TimeoutError(
                    "role propagation: the run budget ended first; not graded") from exc
            return err["Code"], err["Message"]
        if on_success is not None:
            on_success(result)
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_function_retrying(ctx, lam, kwargs: dict) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = err["Code"] == "InvalidParameterValueException" and any(
                t in err.get("Message", "") for t in _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State") in ("Active", "Failed"), timeout_s=600,
                 what=f"function {name} leaves Pending")
    assert conf["State"] == "Active", f"{name}: {conf['State']!r} {conf.get('StateReason')!r}"
    return name


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


def _poll(ctx, probe, done, *, timeout_s, interval_s=2.0, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _delete_mount_target(ctx, efs, fs_id, mt_id) -> None:
    """Delete the mount target and wait until the file system lists none, so it can delete."""
    _teardown(lambda: efs.delete_mount_target(MountTargetId=mt_id), "MountTargetNotFound")()
    _poll(ctx, lambda: efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"],
          lambda mts: mts == [], timeout_s=300, what=f"{fs_id} has no mount targets")


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
    _poll(ctx, lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["LifeCycleState"],
          lambda s: s == "available", timeout_s=120, what=f"{ap_id} available")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
