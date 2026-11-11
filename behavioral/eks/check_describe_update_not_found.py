"""describe-update-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _create_cluster_when_role_ready(c, timeout_s=90, interval_s=5, **kwargs):
    """CreateCluster, retrying while EKS has not yet observed a just-created role.

    IAM is eventually consistent: EKS can reject a brand-new role for a bounded window
    after it is created, so this bounds that wait to the specific error it causes
    instead of sleeping blind.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            return c.create_cluster(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterException" or "role" not in err.get("Message", "").lower():
                raise
            if time.time() >= deadline:
                raise AssertionError(
                    f"role {kwargs.get('roleArn')} never became visible to EKS within {timeout_s}s: {err}"
                ) from exc
            time.sleep(interval_s)


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=10, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


CHECK = "describe-update-not-found"
GROUP = 'error-semantics'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an ACTIVE cluster, DescribeUpdate returns the LoggingUpdate UpdateClusterConfig created, which ends
    Successful, while a well-formed unknown update id fails with ResourceNotFoundException and its exact
    message.
    """
    c = ctx.client("eks")

    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + "eks-du-")
    _create_cluster_when_role_ready(
        c,
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": _subnet_ids(ctx),
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={
            "authenticationMode": "API_AND_CONFIG_MAP",
            "bootstrapClusterCreatorAdminPermissions": True,
        },
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))

    cluster = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500, interval_s=20, desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"

    update = c.update_cluster_config(
        name=name,
        logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
    )["update"]
    real_update_id = update["id"]
    # Registered after DeleteCluster, so it runs first: DeleteCluster is refused while this
    # update is InProgress, so an early assertion failure must not strand the cluster.
    ctx.on_cleanup(lambda: _wait_for(
        lambda: c.describe_update(name=name, updateId=real_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=420, interval_s=10, desc=f"update {real_update_id} terminal before delete",
    ))

    # Positive control: DescribeUpdate succeeds for a real update on a real cluster --
    # without this, "rejects an unknown update id" is indistinguishable from "rejects
    # every DescribeUpdate call".
    seen = c.describe_update(name=name, updateId=real_update_id)["update"]
    assert seen["id"] == real_update_id, seen
    assert seen["type"] == "LoggingUpdate", seen

    # The negative under test: same real cluster, a well-formed but nonexistent update id.
    ghost_update_id = str(uuid.uuid4())
    code, msg = _expect_error(
        lambda: c.describe_update(name=name, updateId=ghost_update_id)
    )
    assert code == "ResourceNotFoundException", code
    expected = f"No update found for ID: {ghost_update_id}"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Drive the real update to a terminal state so DeleteCluster in cleanup is not
    # blocked by an update still InProgress.
    terminal = _wait_for(
        lambda: c.describe_update(name=name, updateId=real_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=420, interval_s=10, desc=f"update {real_update_id} terminal",
    )
    assert terminal["status"] == "Successful", terminal


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
