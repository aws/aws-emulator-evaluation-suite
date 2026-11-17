"""create-cluster-public-access-cidr-quota-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-public-access-cidr-quota-rejected"
GROUP = "negative-boundary"
SERVICES = ["ec2", "eks", "iam"]

#: EKS's fixed, non-adjustable quota on public endpoint access CIDR ranges per cluster.
_CIDR_QUOTA = 40

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_K8S_VERSION = "1.33"
_GONE_DEADLINE_S = 900


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A create whose resourcesVpcConfig.publicAccessCidrs holds one more entry than EKS's
    public-endpoint-access-CIDR-ranges-per-cluster quota is refused before any per-entry check
    runs; the same create with one legal CIDR is accepted and the allow-list round-trips."""
    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")
    role_arn = _service_role(ctx)
    subnet_ids = ctx.network().subnet_ids[:2]

    over_quota_cidrs = [f"192.0.2.{i}/32" for i in range(1, _CIDR_QUOTA + 2)]
    over_quota = ctx.unique_name("sim2real-ekscidrq-")
    got = _expect_error(lambda: _create(ctx, eks, over_quota, role_arn, subnet_ids, over_quota_cidrs))
    assert got == (
        "InvalidParameterException",
        f"The publicAccessCidrs list should not be larger than {_CIDR_QUOTA}.",
    ), (
        f"creating a cluster with {len(over_quota_cidrs)} publicAccessCidrs entries (one over "
        f"the quota of {_CIDR_QUOTA}) must refuse with InvalidParameterException and its exact "
        f"message; got {got!r}")
    gone = _expect_error(lambda: eks.describe_cluster(name=over_quota))
    assert gone == ("ResourceNotFoundException", f"No cluster found for name: {over_quota}."), (
        f"the refused create must leave no cluster {over_quota!r}; describe returned {gone!r}")

    # Positive control: a legal publicAccessCidrs entry, below the quota, is accepted. EKS refuses
    # every documentation and private range for this field, so the control uses a real address the
    # check owns rather than one of the reserved ranges the negative used to hit the list length.
    allowed = f"{_owned_public_ip(ctx, ec2)}/32"
    ok_name = ctx.unique_name("sim2real-ekscidrq-")
    created = _create(ctx, eks, ok_name, role_arn, subnet_ids, [allowed])
    assert created["status"] == "CREATING", (
        f"the control create should start CREATING; got {created.get('status')!r}")
    cidrs = eks.describe_cluster(name=ok_name)["cluster"]["resourcesVpcConfig"]["publicAccessCidrs"]
    assert cidrs == [allowed], f"the control's allow-list must round-trip; got {cidrs!r}"


def _expect_error(fn) -> tuple[str, str]:
    """(ErrorCode, Message) fn() raises. RAISES when the call succeeds: real AWS rejects it."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError("the call SUCCEEDED; real AWS rejects it, so there is no error")


def _absent_code(fn) -> str:
    """The error code fn() raises, or "<succeeded>" when it succeeds — for asserting an ABSENCE."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "<succeeded>"


def _quiet(fn, *not_found: str) -> None:
    """Run one teardown call; only the resource's own not-found codes mean it is gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found:
            raise


def _service_role(ctx) -> str:
    """A cluster service role of our own, trusting eks.amazonaws.com and carrying the cluster policy."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ekscidrq-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CLUSTER_POLICY)
    ctx.on_cleanup(lambda: _quiet(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_CLUSTER_POLICY), "NoSuchEntity"))
    return arn


def _owned_public_ip(ctx, ec2) -> str:
    """A real, unassociated public address the check allocates: EKS refuses every reserved and
    private range in publicAccessCidrs, so a legal entry must be one the check actually owns."""
    eip = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip",
                             "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: _quiet(
        lambda: ec2.release_address(AllocationId=eip["AllocationId"]), "InvalidAllocationID.NotFound"))
    return eip["PublicIp"]


def _create(ctx, eks, name: str, role_arn: str, subnet_ids: list[str], cidrs: list[str]) -> dict:
    """create_cluster with the teardown registered BEFORE the create; returns the created cluster."""
    ctx.on_cleanup(lambda: _drop_cluster_net(eks, name))
    return eks.create_cluster(
        name=name, version=_K8S_VERSION, roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids, "publicAccessCidrs": cidrs},
    )["cluster"]


def _drop_cluster(eks, name: str) -> bool:
    """Delete the cluster and wait until it no longer describes. True when it is gone.

    EKS accepts DeleteCluster while the cluster is still CREATING, which keeps this cheap.
    """
    deadline = time.monotonic() + _GONE_DEADLINE_S
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return True
            if code == "InvalidParameterException":
                return True  # the name never passed validation, so there is no cluster
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        if _absent_code(lambda: eks.describe_cluster(name=name)) == "ResourceNotFoundException":
            return True
        time.sleep(2)
    return False


def _drop_cluster_net(eks, name: str) -> None:
    """The on_cleanup slot for _drop_cluster: raises if the cluster still describes after delete."""
    if not _drop_cluster(eks, name):
        raise AssertionError(f"eks cluster {name} still describes {_GONE_DEADLINE_S}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
