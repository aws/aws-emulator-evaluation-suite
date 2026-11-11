"""delete-dependents-out-of-order-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dependents-out-of-order-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComputeNodeGroup while a queue uses the group and DeleteCluster while it has an ACTIVE
    queue and node group get ConflictException with their exact messages and leave both ACTIVE; deleting
    queue, node group, then cluster succeeds."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _create_subnet_and_security_group(ctx)
    cluster_name = ctx.unique_name("sim2real-delorder").replace("_", "-")

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": "25.05"},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
    )
    cluster_id = create_resp["cluster"]["id"]
    ctx.on_cleanup(lambda: _delete_cluster_best_effort(ctx, cluster_id))

    cluster = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert cluster["status"] == "ACTIVE", f"cluster reached {cluster['status']} instead of ACTIVE"

    launch_template_id = _create_launch_template(ctx, security_group_id)
    profile_arn = _create_pcs_instance_profile(ctx, "AWSPCS-sim2real-delorder")
    ami_id = _get_pcs_recommended_ami(ctx)

    cng = _create_active_compute_node_group(
        pcs,
        cluster_id=cluster_id,
        name=ctx.unique_name("sim2real-cng").replace("_", "-")[:24],
        subnet_id=subnet_id,
        launch_template_id=launch_template_id,
        profile_arn=profile_arn,
        ami_id=ami_id,
    )
    cng_id = cng["id"]
    assert cng["status"] == "ACTIVE", f"node group reached {cng['status']} instead of ACTIVE: {cng.get('errorInfo')}"

    queue_resp = pcs.create_queue(
        clusterIdentifier=cluster_id,
        queueName=ctx.unique_name("sim2real-q").replace("_", "-")[:24],
        computeNodeGroupConfigurations=[{"computeNodeGroupId": cng_id}],
    )
    queue_id = queue_resp["queue"]["id"]
    queue = _poll_until(
        lambda: pcs.get_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)["queue"],
        lambda q: q["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert queue["status"] == "ACTIVE", f"queue reached {queue['status']} instead of ACTIVE"

    # --- deleting the node group while the queue still references it is rejected ---
    code = message = None
    try:
        pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = "AWS PCS can't delete the compute node group you specified because the cluster has associated queues."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    unchanged_cng = pcs.get_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)[
        "computeNodeGroup"
    ]
    assert unchanged_cng["status"] == "ACTIVE", "node group left ACTIVE state despite rejected delete"

    # --- deleting the cluster while the queue/node group are still ACTIVE is rejected ---
    code = message = None
    try:
        pcs.delete_cluster(clusterIdentifier=cluster_id)
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = (
        "AWS PCS can't delete the cluster you specified because it has associated queues or compute node groups."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    unchanged_cluster = pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    assert unchanged_cluster["status"] == "ACTIVE", "cluster left ACTIVE state despite rejected delete"

    # --- positive control: deleting in the correct order fully succeeds ---
    pcs.delete_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)
    _poll_until(
        lambda: _get_queue_or_none(pcs, cluster_id, queue_id),
        lambda q: q is None,
        timeout_s=600.0,
        interval_s=10.0,
    )
    pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)
    _poll_until(
        lambda: _get_node_group_or_none(pcs, cluster_id, cng_id),
        lambda g: g is None or g["status"] == "DELETED",
        timeout_s=900.0,
        interval_s=15.0,
    )
    pcs.delete_cluster(clusterIdentifier=cluster_id)
    _poll_until(
        lambda: _get_cluster_or_none(pcs, cluster_id),
        lambda c: c is None,
        timeout_s=1200.0,
        interval_s=15.0,
    )


def _create_subnet_and_security_group(ctx) -> tuple[str, str]:
    """A subnet in a VPC this check creates, plus that VPC's own default security group.

    CreateCluster's networking block requires securityGroupIds alongside subnetIds. The VPC and
    subnet are removed at cleanup, after the cluster that holds ENIs in them is gone."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-pcs-net")
    tag_list = [{"Key": "Name", "Value": name}, {"Key": "sim2real-check", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_list}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_list}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return subnet_id, groups[0]["GroupId"]


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Delete, retrying while ENIs a deleted PCS resource left behind still hold the VPC."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


def _create_launch_template(ctx, security_group_id) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-pcs-lt")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        # PCS rejects a launch template with no interface-level security groups:
        # "In a launch template, either specify Groups for each network interface, or
        # specify SecurityGroupIds."
        LaunchTemplateData={"InstanceType": "c5.large", "SecurityGroupIds": [security_group_id]},
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_pcs_instance_profile(ctx, name_prefix) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _delete_role_best_effort(ctx, name))
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSPCSComputeNodePolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSPCSComputeNodePolicy")
    )
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: _delete_instance_profile_best_effort(ctx, name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    profile = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
    return profile["Arn"]


def _delete_role_best_effort(ctx, name) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile_best_effort(ctx, name) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _get_pcs_recommended_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    names = []
    for page in ssm.get_paginator("get_parameters_by_path").paginate(Path="/aws/service/pcs", Recursive=True):
        names.extend(p["Name"] for p in page.get("Parameters", []))
    recommended = [n for n in names if n.endswith("/x86_64/latest/ami-id")]
    if not recommended:
        raise AssertionError(f"no x86_64 PCS AMI parameter found under /aws/service/pcs; saw {names}")
    return ssm.get_parameter(Name=sorted(recommended)[0])["Parameter"]["Value"]


def _create_active_compute_node_group(
    pcs, *, cluster_id, name, subnet_id, launch_template_id, profile_arn, ami_id, timeout_s=240.0, interval_s=15.0
):
    """IAM reports no point at which a fresh role/instance profile is visible to PCS, so the bound
    on that propagation is a retry at first use: a synchronous AccessDeniedException ("doesn't pass
    iam:PassRole verification"), or an async CREATE_FAILED whose errorInfo names only
    IamInstanceProfileNotFound. Anything else is returned for the caller's assertion to report."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pcs.create_compute_node_group(
                clusterIdentifier=cluster_id,
                computeNodeGroupName=name,
                amiId=ami_id,
                subnetIds=[subnet_id],
                customLaunchTemplate={"id": launch_template_id, "version": "1"},
                iamInstanceProfileArn=profile_arn,
                scalingConfiguration={"minInstanceCount": 0, "maxInstanceCount": 0},
                instanceConfigs=[{"instanceType": "c5.large"}],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            continue
        cng_id = resp["computeNodeGroup"]["id"]
        cng = _poll_until(
            lambda: pcs.get_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)[
                "computeNodeGroup"
            ],
            lambda g: g["status"] in ("ACTIVE", "CREATE_FAILED"),
            timeout_s=1200.0,
            interval_s=15.0,
        )
        if cng["status"] == "ACTIVE":
            return cng
        error_codes = {e.get("code") for e in (cng.get("errorInfo") or [])}
        if error_codes != {"IamInstanceProfileNotFound"} or time.monotonic() >= deadline:
            return cng
        pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)
        _poll_until(
            lambda: _get_node_group_or_none(pcs, cluster_id, cng_id),
            lambda g: g is None or g["status"] == "DELETED",
            timeout_s=300.0,
            interval_s=10.0,
        )
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_cluster_or_none(pcs, cluster_id):
    try:
        return pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_node_group_or_none(pcs, cluster_id, cng_id):
    try:
        return pcs.get_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)[
            "computeNodeGroup"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_queue_or_none(pcs, cluster_id, queue_id):
    try:
        return pcs.get_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)["queue"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_dependents_best_effort(ctx, cluster_id, timeout_s=900.0, interval_s=15.0) -> None:
    pcs = ctx.client("pcs")
    try:
        for q in pcs.list_queues(clusterIdentifier=cluster_id).get("queues", []):
            try:
                pcs.delete_queue(clusterIdentifier=cluster_id, queueIdentifier=q["id"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and pcs.list_queues(clusterIdentifier=cluster_id).get("queues"):
            time.sleep(interval_s)
        for g in pcs.list_compute_node_groups(clusterIdentifier=cluster_id).get("computeNodeGroups", []):
            if g["status"] != "DELETED":
                try:
                    pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=g["id"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and any(
            g["status"] != "DELETED"
            for g in pcs.list_compute_node_groups(clusterIdentifier=cluster_id).get("computeNodeGroups", [])
        ):
            time.sleep(interval_s)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_cluster_best_effort(ctx, cluster_id, timeout_s=1200.0, interval_s=15.0) -> None:
    pcs = ctx.client("pcs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _get_cluster_or_none(pcs, cluster_id)
        if cluster is None:
            return
        if cluster["status"] in ("ACTIVE", "SUSPENDED", "CREATE_FAILED"):
            try:
                pcs.delete_cluster(clusterIdentifier=cluster_id)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ConflictException":
                    _delete_dependents_best_effort(ctx, cluster_id)
                    continue
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        # Wait for the cluster to go: its ENIs hold the subnet and VPC that cleanup deletes next.
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
