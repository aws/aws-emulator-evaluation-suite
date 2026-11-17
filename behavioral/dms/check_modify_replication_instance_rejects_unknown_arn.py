"""modify-replication-instance-rejects-unknown-arn."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "modify-replication-instance-rejects-unknown-arn"
GROUP = "validation"
SERVICES = ["dms", "ec2", "iam"]

_DMS_VPC_ROLE = "dms-vpc-role"  # AWS fixes this name; a subnet group requires it to exist.
_DMS_VPC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"
_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "dms.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _error(fn) -> tuple[str, str]:
    """The exact error code and message AWS returned, or a failure if the call unexpectedly succeeded."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — the code and message are the subject of the assertion
        response = getattr(exc, "response", None)
        assert isinstance(response, dict), f"expected a modelled AWS error, got {exc!r}"
        return response["Error"]["Code"], response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _ensure_dms_vpc_role(iam) -> None:
    """Create the fixed-name service role a replication subnet group needs, if it is absent.

    The name is not ours to randomize, so this is create-if-absent and never torn down: deleting
    an account-global prerequisite out from under a sibling run is worse than leaving it.
    """
    try:
        iam.get_role(RoleName=_DMS_VPC_ROLE)
        return
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.create_role(RoleName=_DMS_VPC_ROLE, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST))
    iam.attach_role_policy(RoleName=_DMS_VPC_ROLE, PolicyArn=_DMS_VPC_POLICY)


def _instance(dms, arn: str) -> dict | None:
    """The replication instance named by ``arn``, or ``None``.

    A filtered DescribeReplicationInstances that matches nothing raises ResourceNotFoundFault
    rather than returning an empty list, so that code means absent, not an error to propagate.
    """
    from botocore.exceptions import ClientError

    try:
        insts = dms.describe_replication_instances(
            Filters=[{"Name": "replication-instance-arn", "Values": [arn]}]
        )["ReplicationInstances"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundFault":
            return None
        raise
    return insts[0] if insts else None


def _await_available(dms, arn: str, budget_s: float, poll_s: float = 20.0) -> dict:
    """Poll the instance until its status is ``available``; fail loud on a terminal non-success."""
    deadline = time.time() + budget_s
    seen: list[str] = []
    while time.time() < deadline:
        inst = _instance(dms, arn)
        status = inst["ReplicationInstanceStatus"] if inst else "gone"
        if not seen or seen[-1] != status:
            seen.append(status)
        if status == "available":
            return inst
        assert status not in ("deleting", "failed", "incompatible-parameters"), (
            f"replication instance {arn} reached {status!r} (saw {seen}), expected 'available'"
        )
        time.sleep(poll_s)
    raise AssertionError(f"replication instance {arn} never reached 'available' within "
                         f"{budget_s:.0f}s (saw {seen})")


# Not-found codes a teardown treats as "already gone", and the codes a dependent delete is
# retried against while an earlier delete in the chain is still releasing its dependency.
_GONE_CODES = ("ResourceNotFoundFault", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound")
_BUSY_CODES = ("InvalidResourceStateFault", "DependencyViolation")


def _code(exc) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _teardown_wait(delete, gone, budget_s: float, poll_s: float = 15.0) -> None:
    """Issue ``delete()``, then poll ``gone()`` to true; raise if it never converges."""
    from botocore.exceptions import ClientError

    try:
        delete()
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise
    deadline = time.time() + budget_s
    while not gone():
        if time.time() >= deadline:
            raise AssertionError(f"resource still present {budget_s:.0f}s after its delete")
        time.sleep(poll_s)


def _teardown_retry(delete, budget_s: float, poll_s: float = 5.0) -> None:
    """Retry ``delete()`` while it is refused as busy; done on success or the resource's own
    not-found code; raise everything else, including a timed-out busy retry."""
    from botocore.exceptions import ClientError

    deadline = time.time() + budget_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in _BUSY_CODES or time.time() >= deadline:
                raise
            time.sleep(poll_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyReplicationInstance on an unknown ARN fails with ResourceNotFoundFault and leaves
    the real instance's AutoMinorVersionUpgrade untouched; the same call against the real ARN
    with ApplyImmediately succeeds and DescribeReplicationInstances reports the change in place.

    Reference: https://docs.aws.amazon.com/dms/latest/APIReference/API_ModifyReplicationInstance.html
    """
    dms = ctx.client("dms")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    _ensure_dms_vpc_role(iam)

    vpc_id = ec2.create_vpc(CidrBlock="10.33.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown_retry(lambda: ec2.delete_vpc(VpcId=vpc_id), budget_s=180))

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}]
    )["AvailabilityZones"])[:2]
    assert len(zones) == 2, f"region {ctx.region} offered {zones}, need two availability zones"

    subnet_ids = []
    for i, zone in enumerate(zones):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.33.{i + 1}.0/24",
                               AvailabilityZone=zone)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sn: _teardown_retry(lambda: ec2.delete_subnet(SubnetId=s), budget_s=180))
        subnet_ids.append(sn)

    sng = ctx.unique_name("sim2real-behav-dms-sng-")
    # A dms-vpc-role created moments ago is refused as AccessDeniedFault until IAM propagates it.
    deadline = time.time() + 90
    while True:
        try:
            dms.create_replication_subnet_group(
                ReplicationSubnetGroupIdentifier=sng,
                ReplicationSubnetGroupDescription="sim2real replication instance modify check",
                SubnetIds=subnet_ids,
            )
            break
        except dms.exceptions.AccessDeniedFault as exc:
            if "is not configured properly" not in str(exc) or time.time() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _teardown_retry(
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
        budget_s=120))

    ri_id = ctx.unique_name("sim2real-behav-dms-ri-")
    ri_arn = dms.create_replication_instance(
        ReplicationInstanceIdentifier=ri_id,
        ReplicationInstanceClass="dms.c5.large",
        AllocatedStorage=5,
        ReplicationSubnetGroupIdentifier=sng,
        MultiAZ=False,
        PubliclyAccessible=False,
        AutoMinorVersionUpgrade=True,
    )["ReplicationInstance"]["ReplicationInstanceArn"]
    ctx.on_cleanup(lambda: _teardown_wait(
        lambda: dms.delete_replication_instance(ReplicationInstanceArn=ri_arn),
        lambda: _instance(dms, ri_arn) is None,
        budget_s=900))

    created = _await_available(dms, ri_arn, budget_s=1200)
    assert created["AutoMinorVersionUpgrade"] is True, (
        f"newly created instance reports AutoMinorVersionUpgrade {created['AutoMinorVersionUpgrade']!r}, "
        f"expected True"
    )

    # Break exactly one thing: a well-formed but never-created replication instance ARN.
    bogus_id = ctx.unique_name("sim2real-behav-dms-bogus-")
    bogus_arn = f"arn:aws:dms:{ctx.region}:{ctx.account}:rep:{bogus_id}"
    _NOT_FOUND = ("ResourceNotFoundFault", f"Replication Instance not found: {bogus_arn}")
    code, message = _error(lambda: dms.modify_replication_instance(
        ReplicationInstanceArn=bogus_arn, AutoMinorVersionUpgrade=False, ApplyImmediately=True
    ))
    assert (code, message) == _NOT_FOUND, (
        f"ModifyReplicationInstance on the unknown ARN {bogus_arn} returned ({code!r}, {message!r}), "
        f"expected {_NOT_FOUND!r}"
    )

    # The effect is absent: the real instance is untouched by the refused call.
    untouched = _instance(dms, ri_arn)
    assert untouched["AutoMinorVersionUpgrade"] is True, (
        f"after the refused call, instance {ri_arn} reports AutoMinorVersionUpgrade "
        f"{untouched['AutoMinorVersionUpgrade']!r}, expected it unchanged at True"
    )

    # Positive control: the identical call against the real ARN succeeds...
    modified = dms.modify_replication_instance(
        ReplicationInstanceArn=ri_arn, AutoMinorVersionUpgrade=False, ApplyImmediately=True
    )["ReplicationInstance"]
    assert modified["ReplicationInstanceArn"] == ri_arn, (
        f"ModifyReplicationInstance returned instance {modified['ReplicationInstanceArn']!r}, "
        f"expected {ri_arn!r}"
    )

    # ...and once the instance is back to available, the change is in place on that same ARN.
    settled = _await_available(dms, ri_arn, budget_s=900)
    assert settled["ReplicationInstanceArn"] == ri_arn, (
        f"the settled instance's ARN is {settled['ReplicationInstanceArn']!r}, expected {ri_arn!r}"
    )
    assert settled["AutoMinorVersionUpgrade"] is False, (
        f"after the applied modification, DescribeReplicationInstances reports "
        f"AutoMinorVersionUpgrade {settled['AutoMinorVersionUpgrade']!r}, expected False"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
