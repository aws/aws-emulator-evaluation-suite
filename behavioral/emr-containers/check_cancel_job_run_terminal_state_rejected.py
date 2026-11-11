"""cancel-job-run-terminal-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancel-job-run-terminal-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-containers"]

CLUSTER_ACTIVE_TIMEOUT_S = 1200
CLUSTER_DELETE_TIMEOUT_S = 900
VC_REACHABLE_TIMEOUT_S = 420


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelJobRun on a job run that is already in a terminal state (CANCELLED) is
    rejected with ValidationException; the initial cancel that produced that terminal
    state is the positive control proving CancelJobRun itself works."""
    emrc = ctx.client("emr-containers")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
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

    # Positive control: cancelling a live job run succeeds.
    emrc.cancel_job_run(id=job_id, virtualClusterId=vc_id)
    final_state = _poll_until(
        lambda: emrc.describe_job_run(id=job_id, virtualClusterId=vc_id)["jobRun"]["state"],
        lambda st: st in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert final_state == "CANCELLED", f"expected CANCELLED, got {final_state}"

    # Negative: cancelling the now-terminal job run again is rejected.
    code, message = _client_error(lambda: emrc.cancel_job_run(id=job_id, virtualClusterId=vc_id))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = f"Job run {job_id} is not in a cancellable state"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: state is still exactly CANCELLED, not mutated by the failed retry.
    state_after = emrc.describe_job_run(id=job_id, virtualClusterId=vc_id)["jobRun"]["state"]
    assert state_after == "CANCELLED", f"expected CANCELLED, got {state_after}"


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


def _delete_vc_ignore(emrc, vc_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.delete_virtual_cluster(id=vc_id)
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
        if state != "TERMINATED":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


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
