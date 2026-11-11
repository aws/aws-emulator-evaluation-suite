"""list-job-runs-state-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-job-runs-state-filter"
GROUP = "data-plane"
SERVICES = ["emr-containers"]

CLUSTER_ACTIVE_TIMEOUT_S = 1200
CLUSTER_DELETE_TIMEOUT_S = 900
VC_REACHABLE_TIMEOUT_S = 420


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListJobRuns' states filter actually filters: a job run that we cancel to
    CANCELLED shows up when filtering for CANCELLED and does not show up when
    filtering for a disjoint state like RUNNING."""
    emrc = ctx.client("emr-containers")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    cluster_id, namespace = _eks_fixture(ctx)

    vc = _create_virtual_cluster(
        ctx,
        emrc,
        name=ctx.unique_name("sim2real-vc-"),
        clientToken=ctx.unique_name("tok-"),
        containerProvider={
            "type": "EKS",
            "id": cluster_id,
            "info": {"eksInfo": {"namespace": namespace}},
        },
    )
    vc_id = vc["id"]
    ctx.on_cleanup(lambda: _delete_vc(emrc, vc_id))

    job = emrc.start_job_run(
        virtualClusterId=vc_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        releaseLabel="emr-6.15.0-latest",
        jobDriver={
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
        },
    )
    job_id = job["id"]
    emrc.cancel_job_run(id=job_id, virtualClusterId=vc_id)
    _poll_until(
        lambda: emrc.describe_job_run(id=job_id, virtualClusterId=vc_id)["jobRun"]["state"],
        lambda st: st == "CANCELLED",
        timeout_s=120,
        interval_s=3,
    )

    matching = emrc.list_job_runs(virtualClusterId=vc_id, states=["CANCELLED"])["jobRuns"]
    assert any(j["id"] == job_id for j in matching), (
        f"expected job run {job_id} in states=[CANCELLED] listing, got ids="
        f"{[j['id'] for j in matching]}"
    )

    disjoint = emrc.list_job_runs(virtualClusterId=vc_id, states=["RUNNING"])["jobRuns"]
    assert not any(j["id"] == job_id for j in disjoint), (
        f"expected job run {job_id} absent from states=[RUNNING] listing, but it was present: "
        f"{[j['id'] for j in disjoint]}"
    )


# ===== helpers =====
def _eks_fixture(ctx):
    """Create a node-less EKS cluster in the shared network and return (cluster, namespace).

    On an API-auth cluster EMR on EKS registers its own access entry, and the built-in
    namespaces exist from creation, so a virtual cluster can register with no kubectl step.
    """
    import json

    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account has no shared network VPC to host the EKS cluster"
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for subnet in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    assert len(subnet_ids) >= 2, f"the shared network spans fewer than two AZs: {by_az!r}"

    role_name = ctx.unique_name("sim2real-emrc-clusrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    cluster_name = ctx.unique_name("sim2real-emrc-eks-")
    deadline = time.monotonic() + 60
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            )
            break
        except ClientError as err:
            # A just-created cluster role is not yet assumable by EKS for a few seconds.
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_eks_cluster(eks, cluster_name))

    left = ctx.time_left()
    deadline = time.monotonic() + (
        CLUSTER_ACTIVE_TIMEOUT_S if left is None else min(CLUSTER_ACTIVE_TIMEOUT_S, left)
    )
    status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    while status != "ACTIVE":
        assert status == "CREATING", f"EKS cluster {cluster_name!r} went {status!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"EKS cluster {cluster_name!r} still {status!r} at the deadline")
        time.sleep(2)
        status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    return cluster_name, "default"


def _delete_eks_cluster(eks, cluster_name) -> None:
    from botocore.exceptions import ClientError

    try:
        eks.delete_cluster(name=cluster_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + CLUSTER_DELETE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"EKS cluster {cluster_name!r} was not deleted within the deadline")


def _create_virtual_cluster(ctx, emrc, **kwargs):
    """CreateVirtualCluster, retried while EMR on EKS is still connecting to the new cluster.

    Right after the cluster turns ACTIVE, EMR reports it unreachable and then, until its own
    access entry takes effect, reports the namespace as missing; both clear within minutes.
    """
    from botocore.exceptions import ClientError

    namespace = kwargs["containerProvider"]["info"]["eksInfo"]["namespace"]
    transient = (
        "is not reachable as its connection is currently being updated",
        f"Required resource {namespace} not found on the cluster.",
    )
    left = ctx.time_left()
    deadline = time.monotonic() + (
        VC_REACHABLE_TIMEOUT_S if left is None else min(VC_REACHABLE_TIMEOUT_S, left)
    )
    while True:
        try:
            return emrc.create_virtual_cluster(**kwargs)
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if not any(t in message for t in transient) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_vc(emrc, vc_id: str) -> None:
    """Teardown: done once the virtual cluster is gone, TERMINATING or TERMINATED; the refusal while a job
    run or endpoint is still active is retried to a deadline; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            state = emrc.describe_virtual_cluster(id=vc_id)["virtualCluster"]["state"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if state in ("TERMINATING", "TERMINATED"):
            return
        try:
            emrc.delete_virtual_cluster(id=vc_id)
            return
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if message != "VirtualCluster has active resources" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
