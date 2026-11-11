"""emr-cluster-logs-uploaded-to-s3-log-uri-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-cluster-logs-uploaded-to-s3-log-uri-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EMR cluster archives its step and cluster logs to the configured S3 LogUri.

    EMR pushes logs to the LogUri periodically and once more at termination (emr-plan-debugging).
    """
    ctx.on_cleanup(lambda: _delete_emr_default_security_groups(ctx))
    ctx.client("s3")
    bucket = _create_bucket(ctx)
    log_uri = f"s3://{bucket}/logs/"

    service_role = _create_emr_service_role(ctx)
    instance_profile = _create_emr_instance_profile(ctx)

    steps = [
        {
            "Name": "trivial-step",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {"Jar": "command-runner.jar", "Args": ["bash", "-c", "echo emr-log-fidelity-check"]},
        }
    ]
    cluster_id = _run_job_flow(
        ctx,
        name=ctx.unique_name("sim2real-emr-logs-"),
        service_role=service_role,
        instance_profile=instance_profile,
        steps=steps,
        log_uri=log_uri,
        keep_alive=False,
    )
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))

    cluster = _poll_cluster_state(ctx, cluster_id, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=1500.0)
    assert cluster["Status"]["State"] == "TERMINATED", (
        f"expected cluster to auto-terminate cleanly, got {cluster['Status']}"
    )

    prefix = f"logs/{cluster_id}/"
    found = _poll_for_log_objects(ctx, bucket, prefix, timeout_s=600.0, interval_s=20.0)
    assert found, f"no log objects appeared under s3://{bucket}/{prefix} after cluster termination"


# ===== helpers =====


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-logs-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    return profile_name


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
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if steps:
        kwargs["Steps"] = steps
    if log_uri:
        kwargs["LogUri"] = log_uri
    if bootstrap_actions:
        kwargs["BootstrapActions"] = bootstrap_actions

    # Retry RunJobFlow on IAM propagation errors for up to 60 s.
    deadline = time.monotonic() + 60.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = emr.run_job_flow(**kwargs)
            return resp["JobFlowId"]
        except Exception as exc:  # noqa: BLE001 - retry only on transient IAM propagation errors
            msg = str(exc).lower()
            # EMR validates the role/profile ARNs against IAM synchronously; a freshly created
            # role or instance profile can read back as "invalid"/"does not exist" to EMR for a
            # window after IAM's create call returns 200 (measured on real AWS: RunJobFlow raised
            # "Invalid InstanceProfile: ..." on the first attempt here). Retry, do not sleep first.
            transient = (
                "does not exist" in msg
                or "is invalid" in msg
                or "invalid instanceprofile" in msg
                or "invalid servicerole" in msg
                or "not authorized" in msg
            )
            if time.monotonic() < deadline and transient:
                time.sleep(2)
                continue
            raise


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


def _poll_for_log_objects(ctx: Any, bucket: str, prefix: str, timeout_s: float = 600.0, interval_s: float = 20.0) -> bool:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=5)
        if resp.get("KeyCount", 0) > 0:
            return True
        time.sleep(interval_s)
    return False



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
