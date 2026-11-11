"""cfn-deploy-emr-cluster-missing-instance-profile-negative."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-emr-cluster-missing-instance-profile-negative"
GROUP = "overly-permissive"
SERVICES = ["emr", "glue", "s3"]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN-deployed EMR cluster whose JobFlowRole names an instance profile that does not
    exist is rejected before any EC2 instance (and hence any S3/LogUri access) is ever created;
    a stack with a valid instance profile in the same file is accepted."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    emr = ctx.client("emr")
    cfn = ctx.client("cloudformation")
    subnet = _pick_subnet(ctx)

    # --- negative: JobFlowRole names an instance profile that was never created ---
    bad_cluster_name = _xname(ctx, "emrbad")
    bogus_profile_name = _xname(ctx, "no-such-profile")
    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LogBucket": {"Type": "AWS::S3::Bucket"},
                "EMRServiceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "elasticmapreduce.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
                        ],
                    },
                },
                "EMRCluster": {
                    "Type": "AWS::EMR::Cluster",
                    "DependsOn": ["EMRServiceRole", "LogBucket"],
                    "Properties": {
                        "Name": bad_cluster_name,
                        "ReleaseLabel": "emr-6.15.0",
                        "Applications": [{"Name": "Hadoop"}],
                        "Instances": {
                            "MasterInstanceGroup": {
                                "InstanceCount": 1,
                                "InstanceType": _INSTANCE_TYPE,
                            },
                            "KeepJobFlowAliveWhenNoSteps": True,
                            "TerminationProtected": False,
                            "Ec2SubnetId": subnet,
                        },
                        "JobFlowRole": bogus_profile_name,
                        "ServiceRole": {"Ref": "EMRServiceRole"},
                        "LogUri": {"Fn::Sub": "s3://${LogBucket}/logs/"},
                        "VisibleToAllUsers": True,
                    },
                },
            },
        }
    )

    bad_stack_name = _xname(ctx, "stk")
    bad_stack = _create_stack(ctx, bad_template, teardown_deadline, stack_name=bad_stack_name, timeout_s=600)
    final_status = bad_stack["StackStatus"]
    assert final_status == "ROLLBACK_COMPLETE", (
        f"a stack whose EMR cluster names a nonexistent instance profile must roll back to "
        f"ROLLBACK_COMPLETE, got {final_status!r}"
    )

    # The EMR resource itself must have failed to create -> reason names the instance profile.
    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    emr_failures = [
        e
        for e in events
        if e["LogicalResourceId"] == "EMRCluster"
        and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert emr_failures, "no CREATE_FAILED event recorded for the EMRCluster resource"
    # message varies: the reason embeds EMR's per-request "Request ID", so only the profile it
    # names is graded.
    reason = emr_failures[0]["ResourceStatusReason"]
    assert bogus_profile_name in reason, (
        f"the EMRCluster CREATE_FAILED reason must name the missing instance profile "
        f"{bogus_profile_name!r}, got {reason!r}"
    )

    # No cluster with that name was ever created (no EC2 instance -> no possible S3 access).
    clusters = emr.list_clusters(
        ClusterStates=[
            "STARTING",
            "BOOTSTRAPPING",
            "RUNNING",
            "WAITING",
            "TERMINATING",
            "TERMINATED",
            "TERMINATED_WITH_ERRORS",
        ]
    )["Clusters"]
    assert not any(c["Name"] == bad_cluster_name for c in clusters)

    # --- positive control: a valid instance profile is accepted and the cluster is created ---
    good_cluster_name = _xname(ctx, "emrgood")
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LogBucket2": {"Type": "AWS::S3::Bucket"},
                "EMRServiceRole2": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "elasticmapreduce.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
                        ],
                    },
                },
                "EMREC2Role2": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
                        ],
                    },
                },
                "EMRInstanceProfile2": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "EMREC2Role2"}]},
                },
                "EMRCluster2": {
                    "Type": "AWS::EMR::Cluster",
                    "DependsOn": [
                        "EMRInstanceProfile2",
                        "EMRServiceRole2",
                        "LogBucket2",
                    ],
                    "Properties": {
                        "Name": good_cluster_name,
                        "ReleaseLabel": "emr-6.15.0",
                        "Applications": [{"Name": "Hadoop"}],
                        "Instances": {
                            "MasterInstanceGroup": {
                                "InstanceCount": 1,
                                "InstanceType": _INSTANCE_TYPE,
                            },
                            "KeepJobFlowAliveWhenNoSteps": True,
                            "TerminationProtected": False,
                            "Ec2SubnetId": subnet,
                        },
                        "JobFlowRole": {"Ref": "EMRInstanceProfile2"},
                        "ServiceRole": {"Ref": "EMRServiceRole2"},
                        "LogUri": {"Fn::Sub": "s3://${LogBucket2}/logs/"},
                        "VisibleToAllUsers": True,
                    },
                },
            },
            "Outputs": {
                "ClusterId": {"Value": {"Ref": "EMRCluster2"}},
                "LogBucketName": {"Value": {"Ref": "LogBucket2"}},
            },
        }
    )

    good_stack = _create_stack(ctx, good_template, teardown_deadline, timeout_s=1500)
    assert good_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the stack with a valid instance profile must reach CREATE_COMPLETE, got "
        f"{good_stack['StackStatus']!r} ({good_stack.get('StackStatusReason')!r})"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good_stack.get("Outputs", [])}
    good_cluster_id = outputs["ClusterId"]
    good_bucket = outputs["LogBucketName"]
    # LIFO: the cluster is terminated and awaited, then its log bucket emptied, then the stack goes.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, good_bucket))
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, emr, good_cluster_id, teardown_deadline))

    ready_by = time.monotonic() + min(1200.0, ctx.time_left() or 1200.0)
    good_state = _poll_until(
        lambda: _cluster_state(emr, good_cluster_id, ready_by),
        lambda st: st not in ("STARTING", "BOOTSTRAPPING"),
        timeout_s=1200,
        interval_s=20.0,
        description=f"cluster {good_cluster_id} finishing provisioning",
    )
    assert good_state == "WAITING", (
        f"a keep-alive cluster with no steps must settle in WAITING, got {good_state!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_INSTANCE_TYPE = "m5.xlarge"
_MANAGED_TAG_KEY = "sim2real:managed"
# budget.cleanup_timeout for behavioral/emr__glue__s3, one deadline shared by every teardown of a run.
_CLEANUP_S = 900.0


def _cleanup_left(teardown_deadline) -> float:
    """Seconds left on the shared teardown deadline, less a margin so a teardown raises its own error
    before the runner gives up."""
    return max(0.0, teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - 120.0) - time.monotonic())


def _cluster_state(emr, cluster_id, deadline):
    """The cluster's state; DescribeCluster throttling is retried every 2 s up to `deadline`."""
    while True:
        try:
            return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=_cleanup_left(teardown_deadline),
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _create_stack(ctx, template, teardown_deadline, *, stack_name=None, timeout_s=300.0) -> dict[str, Any]:
    """Create the stack, register its deletion, and return the described stack once its status is
    terminal for a create, whether it succeeded or rolled back."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda st: st in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"CFN stack {name}",
    )
    return cfn.describe_stacks(StackName=name)["Stacks"][0]


def _terminate_and_wait(ctx, emr, cluster_id, teardown_deadline) -> None:
    """Terminate the cluster and wait for TERMINATED, so its log push and its EMR-managed security
    groups are done before the bucket, the stack and the VPC are deleted."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    left = _cleanup_left(teardown_deadline)
    deadline = time.monotonic() + left
    _poll_until(
        lambda: _cluster_state(emr, cluster_id, deadline),
        lambda st: st in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
        timeout_s=left,
        interval_s=2.0,
        description=f"cluster {cluster_id} terminating",
    )


def _retry_ec2_delete(fn, budget_s=300):
    """Run an EC2 teardown call, retrying while its target is still held by something winding down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_vpc(ec2, vpc_id):
    """Delete the VPC after its non-default security groups: EMR creates its managed primary/core
    groups in it, and they reference each other, so their rules are revoked before the deletes."""
    groups = [g for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"] if g["GroupName"] != "default"]
    for g in groups:
        if g.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        _retry_ec2_delete(lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
    _retry_ec2_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))


def _pick_subnet(ctx):
    """A private subnet in a VPC this check creates, in an available AZ that offers _INSTANCE_TYPE.

    Both halves of the AZ choice are load-bearing: describe_instance_type_offerings says nothing
    about zone state, and describe_availability_zones says nothing about instance types. The VPC
    has no internet route; an S3 gateway endpoint is the cluster's only way out. Cleanups run LIFO,
    so the endpoint goes first and the VPC last.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted({z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]} & offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE}; offerings were {sorted(offered)!r}"
    )

    vpc = ec2.create_vpc(CidrBlock="10.94.0.0/16",
                         TagSpecifications=[{"ResourceType": "vpc", "Tags": _xsvc_tags_kv()}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.94.1.0/24", AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _xsvc_tags_kv()}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))

    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]}, {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ctx.region}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _xsvc_tags_kv()}],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, endpoint))
    return subnet


def _delete_vpc_endpoint(ec2, endpoint_id):
    """DeleteVpcEndpoints reports a failed delete in Unsuccessful, not as an error: return once the
    endpoint is gone, raise on anything else."""
    bad = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]).get("Unsuccessful", [])
           if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
    if bad:
        raise RuntimeError(f"delete_vpc_endpoints({endpoint_id}) failed: {bad!r}")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
