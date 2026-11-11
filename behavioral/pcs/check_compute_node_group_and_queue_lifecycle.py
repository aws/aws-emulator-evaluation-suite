"""compute-node-group-and-queue-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compute-node-group-and-queue-lifecycle"
GROUP = "state-machine"
SERVICES = ["pcs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A node group whose role breaks the AWSPCS naming rule gets ValidationException with its exact
    message and is not created; a correct role gives an ACTIVE node group with the requested fields and
    an ACTIVE queue on it; repeat deletes get the exact ResourceNotFoundException."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _create_subnet_and_security_group(ctx)
    cluster_name = ctx.unique_name("sim2real-cngq").replace("_", "-")

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": "25.05"},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
        tags={"Name": cluster_name, "sim2real:managed": "true"},
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
    good_profile_arn = _create_pcs_instance_profile(ctx, name_prefix="AWSPCS-sim2real")
    bad_profile_arn = _create_pcs_instance_profile(ctx, name_prefix="sim2real-badrole", grant_pcs_policy=True)

    cng_name_bad = ctx.unique_name("sim2real-cngbad").replace("_", "-")[:24]
    cng_name_good = ctx.unique_name("sim2real-cnggood").replace("_", "-")[:24]

    # --- naming-convention violation is rejected ---
    # This is an always-invalid-input negative: the bad role's name can never satisfy the AWSPCS
    # naming convention, so there is no restore leg. It is evaluated by PCS's own request
    # validation, not by actually assuming the role, so it needs no propagation wait.
    code = None
    message = None
    try:
        pcs.create_compute_node_group(
            clusterIdentifier=cluster_id,
            computeNodeGroupName=cng_name_bad,
            subnetIds=[subnet_id],
            customLaunchTemplate={"id": launch_template_id, "version": "1"},
            iamInstanceProfileArn=bad_profile_arn,
            scalingConfiguration={"minInstanceCount": 0, "maxInstanceCount": 0},
            instanceConfigs=[{"instanceType": "c5.large"}],
            tags={"Name": cng_name_bad, "sim2real:managed": "true"},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message})"
    # AWS phrases the AWSPCS-prefix/aws-pcs-path violation generically, without naming the ARN.
    expected = (
        "AWS PCS can't access a role associated with the instance profile because the role ARN is "
        "invalid. For more information, see CreateComputeNodeGroup or UpdateComputeNodeGroup in the "
        "API reference."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no node group was created under that rejected name.
    listed = pcs.list_compute_node_groups(clusterIdentifier=cluster_id)["computeNodeGroups"]
    assert all(g["name"] != cng_name_bad for g in listed), "node group created despite bad IAM role naming"

    # --- positive control: a properly-named/pathed role succeeds ---
    cng = _create_active_compute_node_group(
        pcs,
        clusterIdentifier=cluster_id,
        computeNodeGroupName=cng_name_good,
        subnetIds=[subnet_id],
        customLaunchTemplate={"id": launch_template_id, "version": "1"},
        iamInstanceProfileArn=good_profile_arn,
        scalingConfiguration={"minInstanceCount": 0, "maxInstanceCount": 0},
        instanceConfigs=[{"instanceType": "c5.large"}],
        tags={"Name": cng_name_good, "sim2real:managed": "true"},
    )
    cng_id = cng["id"]
    assert cng["status"] == "ACTIVE", f"node group reached {cng['status']} instead of ACTIVE: {cng.get('errorInfo')}"
    assert cng["subnetIds"] == [subnet_id], f"expected subnetIds [{subnet_id}], got {cng['subnetIds']}"
    assert cng["iamInstanceProfileArn"] == good_profile_arn, (
        f"expected iamInstanceProfileArn {good_profile_arn}, got {cng['iamInstanceProfileArn']}"
    )
    assert cng["scalingConfiguration"] == {"minInstanceCount": 0, "maxInstanceCount": 0}, (
        f"expected scalingConfiguration min=0/max=0, got {cng['scalingConfiguration']}"
    )

    # --- queue referencing the node group reaches ACTIVE with that association ---
    queue_name = ctx.unique_name("sim2real-q").replace("_", "-")[:24]
    queue_resp = pcs.create_queue(
        clusterIdentifier=cluster_id,
        queueName=queue_name,
        computeNodeGroupConfigurations=[{"computeNodeGroupId": cng_id}],
        tags={"Name": queue_name, "sim2real:managed": "true"},
    )
    queue_id = queue_resp["queue"]["id"]

    queue = _poll_until(
        lambda: pcs.get_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)["queue"],
        lambda q: q["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert queue["status"] == "ACTIVE", f"queue reached {queue['status']} instead of ACTIVE: {queue.get('errorInfo')}"
    associated_ids = {c["computeNodeGroupId"] for c in queue["computeNodeGroupConfigurations"]}
    assert associated_ids == {cng_id}, f"queue not associated with expected node group: {associated_ids}"

    # --- full teardown in dependency order ---
    pcs.delete_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)
    _poll_until(
        lambda: _get_queue_or_none(pcs, cluster_id, queue_id),
        lambda q: q is None,
        timeout_s=600.0,
        interval_s=10.0,
    )
    # Gone and unusable: a second delete of the same, now-nonexistent queue fails specifically.
    try:
        pcs.delete_queue(clusterIdentifier=cluster_id, queueIdentifier=queue_id)
        raise AssertionError("second delete of an already-deleted queue unexpectedly succeeded")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException on double-delete of queue, got {e.response['Error']['Code']}"
        )
        expected = "AWS PCS couldn't find the queue you specified."
        assert e.response["Error"]["Message"] == expected, (
            f"expected message {expected!r}, got {e.response['Error']['Message']!r}"
        )

    pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)
    _poll_until(
        lambda: _get_node_group_or_none(pcs, cluster_id, cng_id),
        lambda g: g is None or g["status"] == "DELETED",
        timeout_s=900.0,
        interval_s=15.0,
    )
    # Gone and unusable: a second delete of the same, now-nonexistent node group fails specifically.
    try:
        pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=cng_id)
        raise AssertionError("second delete of an already-deleted compute node group unexpectedly succeeded")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException on double-delete of compute node group, got "
            f"{e.response['Error']['Code']}"
        )
        expected = "AWS PCS couldn't find the compute node group you specified."
        assert e.response["Error"]["Message"] == expected, (
            f"expected message {expected!r}, got {e.response['Error']['Message']!r}"
        )

    # The cluster goes last, inside the check's own budget, so cleanup only removes the network.
    _delete_cluster_best_effort(ctx, cluster_id)


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


_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _create_launch_template(ctx, security_group_id) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]
    name = ctx.unique_name("sim2real-pcs-lt")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "InstanceType": "c5.large",
            "ImageId": ami_id,
            "NetworkInterfaces": [{"DeviceIndex": 0, "Groups": [security_group_id]}],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _TAGS}],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_pcs_instance_profile(ctx, name_prefix, grant_pcs_policy=True) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role_best_effort(ctx, name))
    if grant_pcs_policy:
        iam.attach_role_policy(
            RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSPCSComputeNodePolicy"
        )
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(
                RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSPCSComputeNodePolicy"
            )
        )
    iam.create_instance_profile(InstanceProfileName=name, Tags=_TAGS)
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


def _create_active_compute_node_group(pcs, *, timeout_s=180.0, interval_s=20.0, **kwargs):
    """IAM exposes no API that reports a freshly-created role/instance-profile has become
    visible to PCS, so the only correct bound on that cross-service propagation is a retry at
    first use -- either a synchronous AccessDeniedException on the create call itself, or an
    async CREATE_FAILED whose errorInfo names
    IamInstanceProfileNotFound. Anything else is a real failure and is returned as-is for the
    caller's own assertion to report."""
    cluster_id = kwargs["clusterIdentifier"]
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = pcs.create_compute_node_group(**kwargs)
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
    """Safety net: if an earlier assertion failed before the explicit
    teardown steps ran, clear out any leftover queues/node groups so the
    cluster itself is deletable."""
    pcs = ctx.client("pcs")
    try:
        for q in pcs.list_queues(clusterIdentifier=cluster_id).get("queues", []):
            try:
                pcs.delete_queue(clusterIdentifier=cluster_id, queueIdentifier=q["id"])
            except ClientError:
                pass
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and pcs.list_queues(clusterIdentifier=cluster_id).get("queues"):
            time.sleep(interval_s)
        for g in pcs.list_compute_node_groups(clusterIdentifier=cluster_id).get("computeNodeGroups", []):
            if g["status"] != "DELETED":
                try:
                    pcs.delete_compute_node_group(clusterIdentifier=cluster_id, computeNodeGroupIdentifier=g["id"])
                except ClientError:
                    pass
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and any(
            g["status"] != "DELETED"
            for g in pcs.list_compute_node_groups(clusterIdentifier=cluster_id).get("computeNodeGroups", [])
        ):
            time.sleep(interval_s)
    except ClientError:
        pass


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
