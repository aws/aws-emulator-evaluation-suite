"""deep-lambda-2-efs-mount-shared-between-two-functions-and-clientmount-denied."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deep-lambda-2-efs-mount-shared-between-two-functions-and-clientmount-denied"
GROUP = "shared-storage"
SERVICES = ["efs", "lambda"]


_PREFIX = "sim2real-xsvc-efsmnt-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_MOUNT = "/mnt/shared"
_AP_PATH = "/export/lambda"
_POSIX_ID = 1001

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

# The three EC2 network-interface actions a VpcConfig function needs, and NO CloudWatch Logs
# action: without logs permission Lambda never creates /aws/lambda/<fn>, so no log group is left.
_ENI_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                   "ec2:DeleteNetworkInterface"],
        "Resource": "*",
    }],
}

# One handler, deployed as BOTH functions. It never raises: every outcome is in the payload, so a
# FunctionError means the runtime itself failed, never a verdict about the mount.
_HANDLER_SRC = r'''
import base64, hashlib, os

ROOT = "/mnt/shared"


def handler(event, context):
    name = event["name"]
    path = os.path.join(ROOT, name)
    out = {"ismount": os.path.ismount(ROOT), "proc_uid": os.getuid()}
    if event["op"] == "write":
        data = base64.b64decode(event["data_b64"])
        with open(path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with open("/tmp/" + name, "wb") as f:
            f.write(data)
        st = os.stat(path)
        out.update(ok=True, sha256=hashlib.sha256(data).hexdigest(),
                   uid=st.st_uid, gid=st.st_gid)
        return out
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        out.update(ok=False, missing=True, listing=sorted(os.listdir(ROOT)))
        return out
    st = os.stat(path)
    out.update(ok=True, data_b64=base64.b64encode(data).decode(), uid=st.st_uid, gid=st.st_gid,
               tmp_has_it=os.path.exists("/tmp/" + name))
    return out
'''


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code")


def _msg_of(exc):
    return exc.response.get("Error", {}).get("Message", "")


def _zipped(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, done, *, timeout_s, interval_s=1.0, what="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _paginate(client, op, key, **kwargs):
    out = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}] + [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchEntity":
            raise


def _create_role(ctx, iam, label):
    """A Lambda execution role with ENI permissions only; the EFS grant is put later.

    Created BEFORE the VPC so that, with LIFO teardown, the role outlives the ENI drain: Lambda
    releases a function's Hyperplane ENI after DeleteFunction, and the role is left intact until
    that has happened.
    """
    name = ctx.unique_name(f"{_PREFIX}{label}-")
    arn = iam.create_role(
        RoleName=name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(RoleName=name, PolicyName="eni", PolicyDocument=json.dumps(_ENI_POLICY))
    return name, arn


def _efs_client_policy(fs_arn, actions):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": fs_arn}],
    })


def _teardown_vpc(ec2, vpc_id, timeout_s):
    """Delete the VPC and its ENIs, security groups and subnets, retrying until timeout_s.

    Lambda releases a function's Hyperplane ENI asynchronously after DeleteFunction (up to ~20
    minutes); until then the SG and subnets return DependencyViolation, which is retried.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for eni in _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                                 Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                if eni.get("Status") == "available":
                    _delete_quietly(
                        lambda e=eni: ec2.delete_network_interface(
                            NetworkInterfaceId=e["NetworkInterfaceId"]),
                        "InvalidNetworkInterfaceID.NotFound")
            for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups",
                                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                if sg.get("GroupName") != "default":
                    ec2.delete_security_group(GroupId=sg["GroupId"])
            for sn in _paginate(ec2, "describe_subnets", "Subnets",
                                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                ec2.delete_subnet(SubnetId=sn["SubnetId"])
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            if _code_of(exc) == "InvalidVpcID.NotFound":
                return
            if (_code_of(exc) not in ("DependencyViolation", "InvalidNetworkInterface.InUse")
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _delete_file_system(efs, fs_id):
    """Wait for the mount targets to be gone, then delete the file system."""
    deadline = time.monotonic() + 600
    while True:
        try:
            if not efs.describe_mount_targets(FileSystemId=fs_id).get("MountTargets"):
                break
        except ClientError as exc:
            if _code_of(exc) == "FileSystemNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"EFS {fs_id}: mount targets did not drain within 600s")
        time.sleep(2)
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if _code_of(exc) != "FileSystemNotFound":
            raise


def _teardown_in_body(ctx, made):
    """The slow teardown, run from run()'s `finally` rather than ctx.on_cleanup.

    The Hyperplane ENI drain can take many minutes; every step is idempotent and the on_cleanup
    registrations remain as fast backstops.
    """
    lam, efs, ec2 = ctx.client("lambda"), ctx.client("efs"), ctx.client("ec2")
    for fn_name in made.get("fns", []):
        _delete_quietly(lambda f=fn_name: lam.delete_function(FunctionName=f),
                        "ResourceNotFoundException")
    if made.get("ap"):
        _delete_quietly(lambda: efs.delete_access_point(AccessPointId=made["ap"]),
                        "AccessPointNotFound")
    for mt in made.get("mts", []):
        _delete_quietly(lambda m=mt: efs.delete_mount_target(MountTargetId=m), "MountTargetNotFound")
    if made.get("fs"):
        _delete_file_system(efs, made["fs"])
    if made.get("vpc"):
        # Lambda documents up to 20 minutes to release a deleted function's Hyperplane ENI.
        left = ctx.time_left()
        _teardown_vpc(ec2, made["vpc"], timeout_s=1200 if left is None else min(1200, left))


def _delete_quietly(fn, *missing_codes):
    try:
        fn()
    except ClientError as exc:
        if _code_of(exc) not in missing_codes:
            raise


def _two_zones(ec2):
    zones = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}],
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"need two available availability zones, found {zones!r}"
    return zones[:2]


_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions",
                   "CreateNetworkInterface", "unable to configure your environment")


def _create_vpc_function(ctx, lam, role_arn, subnets, sg_id, ap_arn, label, made):
    fn_name = ctx.unique_name(f"{_PREFIX}{label}-")
    made["fns"].append(fn_name)
    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zipped(_HANDLER_SRC)},
        Timeout=30,
        MemorySize=256,
        Description="sim2real-xsvc EFS access point shared between two functions",
        VpcConfig={"SubnetIds": subnets, "SecurityGroupIds": [sg_id]},
        FileSystemConfigs=[{"Arn": ap_arn, "LocalMountPath": _MOUNT}],
        Environment={"Variables": {"NONCE": "0"}},
        Tags=dict(_MANAGED),
    )
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # CreateFunction itself checks the role can mount the access point, so a just-put
            # efs-client policy that IAM has not propagated yet is refused synchronously.
            propagating = (_code_of(exc) == "InvalidParameterValueException" and any(
                s in _msg_of(exc) for s in _ROLE_NOT_READY)) or (
                _code_of(exc) == "AccessDeniedException"
                and "does not have permission to mount" in _msg_of(exc))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_quietly(
        lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"))
    cfg = _poll(lambda: lam.get_function_configuration(FunctionName=fn_name),
                lambda c: c.get("State") in ("Active", "Failed"),
                ctx=ctx,
                timeout_s=_budget_s(ctx, 600), interval_s=1, what=f"{fn_name} leaving State=Pending")
    assert cfg["State"] == "Active", (
        f"{fn_name} entered State={cfg['State']!r}: {cfg.get('StateReason')!r}"
    )
    fsc = cfg.get("FileSystemConfigs") or []
    assert fsc == [{"Arn": ap_arn, "LocalMountPath": _MOUNT}], f"FileSystemConfigs not echoed: {fsc!r}"
    return fn_name


def _invoke(lam, fn_name, event):
    """('ok', payload) or ('error', code, http_status, message) for a service-level refusal."""
    try:
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse",
                          Payload=json.dumps(event).encode())
    except ClientError as exc:
        return ("error", _code_of(exc),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), _msg_of(exc)[:300])
    body = resp["Payload"].read()
    assert resp.get("StatusCode") == 200 and not resp.get("FunctionError"), (
        f"Invoke {fn_name} returned StatusCode={resp.get('StatusCode')!r} "
        f"FunctionError={resp.get('FunctionError')!r}: {body[:500]!r}"
    )
    return ("ok", json.loads(body))


def _cold(ctx, lam, fn_name, nonce):
    """Change one env var so the next Invoke builds a NEW execution environment -- and therefore
    performs a NEW EFS mount with the role's CURRENT permissions. A warm sandbox keeps the mount
    it made at init, so without this a permission change is invisible."""
    lam.update_function_configuration(FunctionName=fn_name,
                                      Environment={"Variables": {"NONCE": str(nonce)}})
    _poll(lambda: lam.get_function_configuration(FunctionName=fn_name),
          lambda c: c.get("LastUpdateStatus") in ("Successful", "Failed"),
          ctx=ctx,
          timeout_s=_budget_s(ctx, 300), what=f"{fn_name} update to settle")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two Lambda functions mounting one EFS access point see the same bytes (but not each
    other's /tmp); removing ClientMount from one role makes its next cold Invoke fail with
    EFSMountFailureException (403) while the other keeps mounting, and restoring it heals.
    """
    ec2 = ctx.client("ec2")
    efs = ctx.client("efs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    zones = _two_zones(ec2)

    # Roles first: LIFO deletes them LAST, after the ENI drain (see _create_role).
    role_a, role_a_arn = _create_role(ctx, iam, "role-a")
    role_b, role_b_arn = _create_role(ctx, iam, "role-b")

    made = {"fns": [], "mts": []}
    try:
        # ---- network: one VPC, two subnets in two derived AZs, one SG allowing NFS from itself.
        vpc_name = ctx.unique_name(_PREFIX + "vpc-")
        vpc_id = ec2.create_vpc(
            CidrBlock="10.77.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(vpc_name)}],
        )["Vpc"]["VpcId"]
        made["vpc"] = vpc_id
        ctx.on_cleanup(lambda: _teardown_vpc(ec2, vpc_id, timeout_s=20))  # backstop only
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        subnets = []
        for i, az in enumerate(zones):
            subnets.append(ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(f"{vpc_name}-{i}")}],
            )["Subnet"]["SubnetId"])
        sg_id = ec2.create_security_group(
            GroupName=vpc_name + "-nfs", Description="sim2real-xsvc NFS between lambda and EFS",
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(vpc_name)}],
        )["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049,
            "UserIdGroupPairs": [{"GroupId": sg_id}],
        }])

        # ---- EFS: file system, a mount target per subnet, IAM-delegating policy, one access point.
        fs_name = ctx.unique_name(_PREFIX + "fs-")
        fs = efs.create_file_system(
            CreationToken=fs_name, PerformanceMode="generalPurpose", Encrypted=True,
            Tags=[{"Key": "Name", "Value": fs_name}] + [{"Key": k, "Value": v} for k, v in _MANAGED.items()],
        )
        fs_id, fs_arn = fs["FileSystemId"], fs["FileSystemArn"]
        made["fs"] = fs_id
        ctx.on_cleanup(lambda: _delete_file_system(efs, fs_id))
        _poll(lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
              lambda s: s == "available", ctx=ctx, timeout_s=_budget_s(ctx, 180), what=f"{fs_id} available")
        mt_ids = []
        for sn in subnets:
            mt = efs.create_mount_target(FileSystemId=fs_id, SubnetId=sn, SecurityGroups=[sg_id])
            mt_ids.append(mt["MountTargetId"])
            made["mts"].append(mt["MountTargetId"])
            ctx.on_cleanup(lambda m=mt["MountTargetId"]: _delete_quietly(
                lambda: efs.delete_mount_target(MountTargetId=m), "MountTargetNotFound"))
        _poll(lambda: [m["LifeCycleState"] for m in efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]],
              lambda states: len(states) == len(subnets) and all(s == "available" for s in states),
              ctx=ctx,
              timeout_s=_budget_s(ctx, 420), interval_s=1, what="both mount targets available")
        # Granting to the account root delegates to identity policies, so the role's
        # ClientMount alone decides whether a function can mount.
        efs.put_file_system_policy(FileSystemId=fs_id, Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DelegateClientAccessToIam",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                "Resource": fs_arn,
            }],
        }))
        ap = efs.create_access_point(
            ClientToken=ctx.unique_name("ap-")[:64], FileSystemId=fs_id,
            PosixUser={"Uid": _POSIX_ID, "Gid": _POSIX_ID},
            RootDirectory={"Path": _AP_PATH, "CreationInfo": {
                "OwnerUid": _POSIX_ID, "OwnerGid": _POSIX_ID, "Permissions": "750"}},
            Tags=[{"Key": "Name", "Value": fs_name + "-ap"}] + [{"Key": k, "Value": v} for k, v in _MANAGED.items()],
        )
        ap_id, ap_arn = ap["AccessPointId"], ap["AccessPointArn"]
        made["ap"] = ap_id
        ctx.on_cleanup(lambda: _delete_quietly(
            lambda: efs.delete_access_point(AccessPointId=ap_id), "AccessPointNotFound"))
        _poll(lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0]["LifeCycleState"],
              lambda s: s == "available", ctx=ctx, timeout_s=_budget_s(ctx, 120), what=f"{ap_id} available")

        full = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
        iam.put_role_policy(RoleName=role_a, PolicyName="efs-client",
                            PolicyDocument=_efs_client_policy(fs_arn, full))
        iam.put_role_policy(RoleName=role_b, PolicyName="efs-client",
                            PolicyDocument=_efs_client_policy(fs_arn, full))

        fn_a = _create_vpc_function(ctx, lam, role_a_arn, subnets, sg_id, ap_arn, "fn-a", made)
        fn_b = _create_vpc_function(ctx, lam, role_b_arn, subnets, sg_id, ap_arn, "fn-b", made)
        lam1 = ctx.client("lambda", config=Config(retries={"max_attempts": 1, "mode": "standard"}))

        # ---- 1. A writes a unique file; B reads back the identical bytes.
        fname = ctx.unique_name("shared-") + ".bin"
        payload = os.urandom(4096) + fname.encode()
        digest = hashlib.sha256(payload).hexdigest()
        wrote = _poll(lambda: _invoke(lam1, fn_a, {"op": "write", "name": fname,
                                                   "data_b64": base64.b64encode(payload).decode()}),
                      lambda r: r[0] == "ok", ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=2,
                      what="function A to mount EFS and write (IAM propagation of ClientMount)")[1]
        assert wrote.get("ok") is True and wrote.get("ismount") is True, f"A's write failed: {wrote!r}"
        assert wrote["sha256"] == digest, f"A wrote {wrote['sha256']!r}, expected {digest!r}"
        assert (wrote["uid"], wrote["gid"]) == (_POSIX_ID, _POSIX_ID), (
            f"the access point must stamp its POSIX identity on new files, got {wrote!r}"
        )

        def _b_reads():
            return _invoke(lam1, fn_b, {"op": "read", "name": fname})

        read = _poll(_b_reads, lambda r: r[0] == "ok", ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=2,
                     what="function B to mount EFS and read")[1]
        assert read.get("ok") is True, f"B could not see the file A wrote to the shared mount: {read!r}"
        got = base64.b64decode(read["data_b64"])
        assert got == payload, (
            f"B read {len(got)} bytes sha256={hashlib.sha256(got).hexdigest()!r}, A wrote {digest!r}"
        )
        assert (read["uid"], read["gid"]) == (_POSIX_ID, _POSIX_ID), f"ownership differs on B: {read!r}"
        assert read.get("tmp_has_it") is False, (
            f"A's /tmp copy must NOT be visible to B -- only the EFS mount is shared: {read!r}"
        )

        # ---- 2. Break exactly one thing: drop ClientMount from B's role (keep ClientWrite).
        iam.put_role_policy(RoleName=role_b, PolicyName="efs-client",
                            PolicyDocument=_efs_client_policy(fs_arn, ["elasticfilesystem:ClientWrite"]))
        nonce = [0]

        def _b_cold_read():
            nonce[0] += 1
            try:
                _cold(ctx, lam, fn_b, nonce[0])
            except ClientError as exc:
                return ("update-refused", _code_of(exc),
                        exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), _msg_of(exc)[:300])
            return _b_reads()

        denied = _poll(_b_cold_read, lambda r: r[0] != "ok", ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
                       what="B's cold Invoke to be refused after ClientMount was removed")
        assert denied[0] == "error", f"refusal came from the wrong layer: {denied!r}"
        assert denied[1] == "EFSMountFailureException", f"expected EFSMountFailureException: {denied!r}"
        assert denied[2] == 403, f"EFSMountFailureException must be HTTP 403: {denied!r}"
        assert denied[3] == (
            f"The function couldn't mount the Amazon EFS file system with access point {ap_arn}."
        ), f"unexpected refusal message: {denied!r}"
        # Differential control in the same window: A, cold too, still mounts and reads.
        _cold(ctx, lam, fn_a, 1)
        ctrl = _invoke(lam1, fn_a, {"op": "read", "name": fname})
        assert ctrl[0] == "ok" and base64.b64decode(ctrl[1].get("data_b64", "")) == payload, (
            f"control: A (ClientMount intact) must still mount and read after a cold start: {ctrl!r}"
        )

        # ---- 3. Repair the one broken thing: B mounts again and reads the same bytes.
        iam.put_role_policy(RoleName=role_b, PolicyName="efs-client",
                            PolicyDocument=_efs_client_policy(fs_arn, full))
        healed = _poll(_b_cold_read, lambda r: r[0] == "ok", ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
                       what="B to mount again after ClientMount was restored")[1]
        assert base64.b64decode(healed.get("data_b64", "")) == payload, (
            f"after restoring ClientMount B must read A's bytes again: {healed!r}"
        )

    finally:
        failed = sys.exc_info()[1]
        try:
            _teardown_in_body(ctx, made)
        except Exception as exc:
            if failed is None:
                raise
            failed.add_note(f"in-body teardown after this failure also failed: {exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
