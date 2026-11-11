"""emr-cluster-missing-s3-logs-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-cluster-missing-s3-logs-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EMR instance role denied s3:PutObject on the log prefix never persists logs there.

    A concurrent sibling cluster with an unrestricted role does get logs under its own prefix, so
    the absence is caused by the permission and the denied-side wait is sized from its latency.
    """
    ctx.on_cleanup(lambda: _delete_emr_default_security_groups(ctx))
    ctx.client("s3")
    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    service_role = _create_emr_service_role(ctx)
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyLogsPut", "Effect": "Deny", "Action": "s3:PutObject", "Resource": f"{bucket_arn}/logs-denied/*"}
        ],
    }
    denied_profile = _create_emr_instance_profile(ctx, extra_policy_document=deny_policy)
    allowed_profile = _create_emr_instance_profile(ctx)

    trivial_steps = [
        {
            "Name": "trivial-step",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", "echo emr-permission-check"]},
        }
    ]

    cluster_denied = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-logdeny-"),
        service_role=service_role,
        instance_profile=denied_profile,
        steps=trivial_steps,
        log_uri=f"s3://{bucket}/logs-denied/",
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_denied))

    cluster_allowed = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-logok-"),
        service_role=service_role,
        instance_profile=allowed_profile,
        steps=trivial_steps,
        log_uri=f"s3://{bucket}/logs-allowed/",
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_allowed))

    _poll_cluster_state(ctx, cluster_denied, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=1500.0)
    _poll_cluster_state(ctx, cluster_allowed, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=1500.0)

    # Positive control: the unrestricted cluster's logs DO show up under its own prefix.
    allowed_found, allowed_elapsed_s = _poll_for_log_objects(ctx, bucket, f"logs-allowed/{cluster_allowed}/", timeout_s=600.0)
    assert allowed_found, "positive control cluster (unrestricted instance role) never got its logs to S3"

    # Negative: the denied cluster never gets logs, held for >= 3x how long the positive control
    # (same wiring, same run) actually took - never a fixed guess shorter than its real latency.
    deny_window_s = max(15.0, 3.0 * allowed_elapsed_s)
    denied_found, _ = _poll_for_log_objects(ctx, bucket, f"logs-denied/{cluster_denied}/", timeout_s=deny_window_s)
    assert not denied_found, (
        "cluster with an instance role denied s3:PutObject on the log prefix still managed to "
        "persist logs there; the emulator is not enforcing the permission boundary"
    )


# ===== helpers =====


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-logperm-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_emr_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-svc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return name


def _create_emr_instance_profile(ctx: Any, extra_policy_document: dict | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    if extra_policy_document is not None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="extra-restriction", PolicyDocument=json.dumps(extra_policy_document)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="extra-restriction"))
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    _wait_for_instance_profile_readable(ctx, profile_name, role_name)
    return profile_name


def _wait_for_instance_profile_readable(
    ctx: Any, profile_name: str, role_name: str, timeout_s: float = 60.0, interval_s: float = 5.0
) -> None:
    """Bounded wait for IAM's own read-after-write lag on the profile/role attachment.

    This does not (and cannot) prove EMR/EC2's cross-service view has caught up too - that gap is
    covered separately by the "does not exist" / "is invalid" / "not authorized" retry already in
    _run_job_flow - but an unconditional sleep guessed at a duration with no stated deadline.
    """
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
            if any(r["RoleName"] == role_name for r in profile.get("Roles", [])):
                return
        except Exception as exc:  # noqa: BLE001 - retry only on IAM read-after-write lag
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"instance profile {profile_name} did not reflect role {role_name} within {timeout_s}s"
    ) from last_exc


def _default_subnet_id(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _run_job_flow(
    ctx: Any,
    *,
    name: str,
    service_role: str,
    instance_profile: str,
    steps: list[dict] | None = None,
    log_uri: str | None = None,
    bootstrap_actions: list[dict] | None = None,
    keep_alive: bool = False,
) -> str:
    emr = ctx.client("emr")
    kwargs: dict[str, Any] = {
        "Name": name,
        "ReleaseLabel": "emr-6.15.0",
        "Applications": [{"Name": "Hadoop"}],
        "Instances": {
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "Market": "ON_DEMAND",
                    "InstanceRole": "MASTER",
                    "InstanceType": "m5.xlarge",
                    "InstanceCount": 1,
                }
            ],
            "Ec2SubnetId": _default_subnet_id(ctx),
            "KeepJobFlowAliveWhenNoSteps": keep_alive,
            "TerminationProtected": False,
        },
        "ServiceRole": service_role,
        "JobFlowRole": instance_profile,
        "VisibleToAllUsers": True,
    }
    if steps:
        kwargs["Steps"] = steps
    if log_uri:
        kwargs["LogUri"] = log_uri
    if bootstrap_actions:
        kwargs["BootstrapActions"] = bootstrap_actions

    last_exc = None
    for attempt in range(6):
        try:
            resp = emr.run_job_flow(**kwargs)
            return resp["JobFlowId"]
        except Exception as exc:  # noqa: BLE001 - retry only on transient IAM propagation errors
            msg = str(exc).lower()
            propagation_lag = (
                "does not exist" in msg
                or "is invalid" in msg
                or "not authorized" in msg
                or "invalid instanceprofile" in msg
            )
            if attempt < 5 and propagation_lag:
                last_exc = exc
                time.sleep(10)
                continue
            raise
    raise last_exc  # pragma: no cover


def _terminate_cluster(ctx: Any, cluster_id: str) -> None:
    emr = ctx.client("emr")
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _poll_cluster_state(
    ctx: Any, cluster_id: str, terminal_states: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0
) -> dict:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    cluster = None
    state = None
    while time.monotonic() < deadline:
        resp = emr.describe_cluster(ClusterId=cluster_id)
        cluster = resp["Cluster"]
        state = cluster["Status"]["State"]
        if state in terminal_states:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {terminal_states} within {timeout_s}s (last={state})")


def _poll_for_log_objects(
    ctx: Any, bucket: str, prefix: str, timeout_s: float = 600.0, interval_s: float = 20.0
) -> tuple[bool, float]:
    s3 = ctx.client("s3")
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=5)
        if resp.get("KeyCount", 0) > 0:
            return True, time.monotonic() - start
        time.sleep(interval_s)
    return False, time.monotonic() - start



def _delete_emr_default_security_groups(ctx, timeout_s=600.0, interval_s=2.0):
    """Delete the ElasticMapReduce-* groups EMR creates in the run's shared network.

    EMR mints these default groups on its first launch in a VPC and never deletes them, so left
    behind they keep the shared network from being deleted. They reference each other, so their
    rules are revoked first; a group still held by a terminating cluster's ENIs is retried.
    """
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id
    deadline = time.monotonic() + timeout_s
    while True:
        groups = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["ElasticMapReduce-*"]},
            ]
        )["SecurityGroups"]
        if not groups:
            return
        for group in groups:
            for key, revoke in (
                ("IpPermissions", ec2.revoke_security_group_ingress),
                ("IpPermissionsEgress", ec2.revoke_security_group_egress),
            ):
                refs = [perm for perm in group.get(key, []) if perm.get("UserIdGroupPairs")]
                if refs:
                    try:
                        revoke(GroupId=group["GroupId"], IpPermissions=refs)
                    except ClientError as e:
                        if e.response["Error"]["Code"] not in (
                            "InvalidGroup.NotFound", "InvalidPermission.NotFound"
                        ):
                            raise
        pending = []
        for group in groups:
            try:
                ec2.delete_security_group(GroupId=group["GroupId"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "DependencyViolation":
                    pending.append(f"{group['GroupId']}: {code}")
                elif code != "InvalidGroup.NotFound":
                    raise
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR default security groups still in {vpc_id}: {pending}")
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
