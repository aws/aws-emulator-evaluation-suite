"""create-managed-endpoint-invalid-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-managed-endpoint-invalid-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-containers"]

CLUSTER_ACTIVE_TIMEOUT_S = 1200
CLUSTER_DELETE_TIMEOUT_S = 900
VC_REACHABLE_TIMEOUT_S = 420
ENDPOINT_SETTLE_TIMEOUT_S = 900
ENDPOINT_DELETE_TIMEOUT_S = 300


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateManagedEndpoint with an unsupported type is rejected with ValidationException
    before anything is provisioned, while a supported type ("JUPYTER_ENTERPRISE_GATEWAY")
    on the same virtual cluster succeeds."""
    emrc = ctx.client("emr-containers")
    iam = ctx.client("iam")

    # Created first: EMR on EKS refuses an execution role IAM has not yet propagated with
    # AccessDeniedException, and the cluster wait below gives it minutes to propagate.
    role_name = ctx.unique_name("sim2real-emrc-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "emr-containers.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    cluster_id, namespace = _eks_fixture(ctx)

    vc = _create_virtual_cluster(
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
    ctx.on_cleanup(lambda: _delete_vc_ignore(emrc, vc_id))

    code, message, status = _client_error(
        lambda: emrc.create_managed_endpoint(
            name=ctx.unique_name("sim2real-ep-"),
            virtualClusterId=vc_id,
            type="SIM2REAL_NOT_A_REAL_ENDPOINT_TYPE",
            releaseLabel="emr-6.15.0-latest",
            executionRoleArn=role_arn,
            clientToken=ctx.unique_name("tok-"),
        )
    )
    assert (code, status) == ("ValidationException", 400), (
        f"expected ValidationException (HTTP 400) for an unsupported endpoint type, "
        f"got {code!r} (HTTP {status}): {message!r}"
    )
    assert message == "Invalid value for argument type", (
        f"expected the exact refusal message 'Invalid value for argument type', got {message!r}"
    )

    # Effect absent: no endpoint got created on the virtual cluster.
    endpoints = emrc.list_managed_endpoints(virtualClusterId=vc_id)["endpoints"]
    assert endpoints == [], f"expected no endpoint after the refused call, got {endpoints!r}"

    # Positive control: a supported type on the same virtual cluster succeeds.
    endpoint = emrc.create_managed_endpoint(
        name=ctx.unique_name("sim2real-ep-"),
        virtualClusterId=vc_id,
        type="JUPYTER_ENTERPRISE_GATEWAY",
        releaseLabel="emr-6.15.0-latest",
        executionRoleArn=role_arn,
        clientToken=ctx.unique_name("tok-"),
    )
    endpoint_id = endpoint["id"]
    ctx.on_cleanup(lambda: _delete_endpoint(emrc, vc_id, endpoint_id))
    listed = [e["id"] for e in emrc.list_managed_endpoints(virtualClusterId=vc_id)["endpoints"]]
    assert listed == [endpoint_id], (
        f"expected ListManagedEndpoints to show only the accepted endpoint {endpoint_id!r}, "
        f"got {listed!r}"
    )
    # A CREATING endpoint is not deletable; wait until it settles so teardown can delete it.
    _wait_endpoint_settled(emrc, vc_id, endpoint_id)


def _eks_fixture(ctx):
    """Create a node-less EKS cluster in the shared network and return (cluster, namespace).

    On an API-auth cluster EMR on EKS registers its own access entry, and the built-in
    namespaces exist from creation, so a virtual cluster can register with no kubectl step.
    """
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


def _delete_vc_ignore(emrc, vc_id: str) -> None:
    from botocore.exceptions import ClientError

    # Refused with "has active resources" while a just-deleted endpoint is still releasing.
    deadline = time.monotonic() + 120
    while True:
        try:
            emrc.delete_virtual_cluster(id=vc_id)
            return
        except ClientError as err:
            # An already-deleted virtual cluster is refused; return only once it reads TERMINATED.
            if err.response["Error"]["Code"] != "ValidationException":
                raise
            try:
                state = emrc.describe_virtual_cluster(id=vc_id)["virtualCluster"]["state"]
            except ClientError as gone:
                if gone.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "TERMINATED":
                return
            if "has active resources" not in str(err) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _endpoint_state(emrc, vc_id: str, endpoint_id: str) -> str:
    return emrc.describe_managed_endpoint(id=endpoint_id, virtualClusterId=vc_id)["endpoint"][
        "state"
    ]


def _wait_endpoint_settled(emrc, vc_id: str, endpoint_id: str) -> str:
    deadline = time.monotonic() + ENDPOINT_SETTLE_TIMEOUT_S
    state = _endpoint_state(emrc, vc_id, endpoint_id)
    while state == "CREATING":
        if time.monotonic() > deadline:
            raise AssertionError(f"endpoint {endpoint_id!r} still CREATING at the deadline")
        time.sleep(2)
        state = _endpoint_state(emrc, vc_id, endpoint_id)
    return state


def _delete_endpoint(emrc, vc_id: str, endpoint_id: str) -> None:
    from botocore.exceptions import ClientError

    # With no worker nodes the endpoint settles in TERMINATED_WITH_ERRORS, already gone.
    if _wait_endpoint_settled(emrc, vc_id, endpoint_id).startswith("TERMINAT"):
        return
    try:
        emrc.delete_managed_endpoint(id=endpoint_id, virtualClusterId=vc_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ValidationException":
            raise
        return
    deadline = time.monotonic() + ENDPOINT_DELETE_TIMEOUT_S
    while not _endpoint_state(emrc, vc_id, endpoint_id).startswith("TERMINATED"):
        if time.monotonic() > deadline:
            raise AssertionError(f"endpoint {endpoint_id!r} not TERMINATED at the deadline")
        time.sleep(15)


def _client_error(fn):
    """(code, message, HTTP status) of the ClientError fn raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"]["HTTPStatusCode"],
        )
    raise AssertionError("expected the call to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
