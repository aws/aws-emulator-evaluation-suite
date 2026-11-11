"""create-virtual-cluster-nonexistent-eks-cluster-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-virtual-cluster-nonexistent-eks-cluster-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-containers"]

CLUSTER_ACTIVE_TIMEOUT_S = 1200
CLUSTER_DELETE_TIMEOUT_S = 900
VC_REACHABLE_TIMEOUT_S = 420


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVirtualCluster naming a nonexistent EKS cluster is rejected with ValidationException
    ("Cluster <id> not found") and registers nothing (ListVirtualClusters for that id is empty),
    while the same call against a real cluster succeeds straight into RUNNING."""
    emrc = ctx.client("emr-containers")
    cluster_id, namespace = _eks_fixture(ctx)

    good = _create_virtual_cluster(
        emrc,
        name=ctx.unique_name("sim2real-vc-"),
        clientToken=ctx.unique_name("tok-"),
        containerProvider={
            "type": "EKS",
            "id": cluster_id,
            "info": {"eksInfo": {"namespace": namespace}},
        },
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_virtual_cluster_and_wait(emrc, good["id"]))
    described = emrc.describe_virtual_cluster(id=good["id"])["virtualCluster"]
    assert described["state"] == "RUNNING", (
        f"positive control virtual cluster {good['id']!r} did not reach RUNNING: "
        f"described state was {described['state']!r}"
    )

    bogus_cluster_id = ctx.unique_name("sim2real-nonexistent-eksc-")
    code, message = _client_error(
        lambda: emrc.create_virtual_cluster(
            name=ctx.unique_name("sim2real-vc-"),
            clientToken=ctx.unique_name("tok-"),
            containerProvider={
                "type": "EKS",
                "id": bogus_cluster_id,
                "info": {"eksInfo": {"namespace": namespace + "x"}},
            },
        )
    )
    assert code == "ValidationException", (
        f"CreateVirtualCluster against nonexistent EKS cluster {bogus_cluster_id!r} "
        f"returned error code {code!r}, expected ValidationException"
    )
    expected = f"Cluster {bogus_cluster_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    survivors = emrc.list_virtual_clusters(containerProviderId=bogus_cluster_id)[
        "virtualClusters"
    ]
    assert survivors == [], (
        f"the rejected CreateVirtualCluster against {bogus_cluster_id!r} left "
        f"{len(survivors)} virtual cluster(s) registered against a container provider "
        f"that does not exist: {survivors!r}"
    )


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

    deadline = time.monotonic() + CLUSTER_ACTIVE_TIMEOUT_S
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


def _create_virtual_cluster(emrc, **kwargs):
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
    deadline = time.monotonic() + VC_REACHABLE_TIMEOUT_S
    while True:
        try:
            return emrc.create_virtual_cluster(**kwargs)
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if not any(t in message for t in transient) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_virtual_cluster_and_wait(emrc, vc_id: str) -> None:
    try:
        emrc.delete_virtual_cluster(id=vc_id)
    except ClientError as exc:
        # An already-deleted virtual cluster is refused; the wait below confirms it is gone.
        if exc.response["Error"]["Code"] != "ValidationException":
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = emrc.describe_virtual_cluster(id=vc_id)["virtualCluster"]["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            break
        if state in ("TERMINATED", "ARRESTED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"virtual cluster {vc_id!r} was not TERMINATED within the deadline")


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    accepted call that AWS refuses fails as accepted, not as an error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
