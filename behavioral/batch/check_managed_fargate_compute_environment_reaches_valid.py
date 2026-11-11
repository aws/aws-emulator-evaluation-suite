"""managed-fargate-compute-environment-reaches-valid."""

from __future__ import annotations
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "managed-fargate-compute-environment-reaches-valid"
GROUP = 'compute-environment'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_VPC_CACHE: dict = {}


def _swallow(fn):
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


def _wait_ce_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (valid for MANAGED CEs). Shared: never deleted.

    Returns (arn, just_created) — callers bound their own wait for IAM's propagation of a
    role created for the first time in this account, rather than sleeping unconditionally.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"], False
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
        return resp["Role"]["Arn"], True
    except Exception as exc:
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from the run's shared network (MANAGED CEs).

    Cached per region for the life of this check so an explicit call and the CE creation
    observe identical values. Raises AssertionError when the account lacks a usable shared network.
    """
    if ctx.region in _VPC_CACHE:
        return _VPC_CACHE[ctx.region]
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
        ).get("Vpcs", [])
    except Exception as exc:
        raise AssertionError(f"cannot describe VPCs in this account: {exc}") from exc
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; cannot build a MANAGED Fargate CE")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not subnet_ids:
        raise AssertionError(f"shared network {vpc_id} has no usable subnets")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"shared network {vpc_id} has no default security group")
    _VPC_CACHE[ctx.region] = (subnet_ids[:3], sgs[0]["GroupId"])
    return _VPC_CACHE[ctx.region]


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it; a failure raises."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    _retry_client_exception(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _wait_compute_environment_gone(bat, name)


def _create_fargate_ce(ctx, bat, name=None, max_vcpus=4, state="ENABLED"):
    """MANAGED / FARGATE compute environment backed by the account's default VPC."""
    subnets, sg = _default_vpc_networking(ctx)
    name = name or ctx.unique_name("sim2real-behav-ce-fg-")
    role_arn, role_just_created = _service_linked_role_arn(ctx)

    def _create():
        return bat.create_compute_environment(
            computeEnvironmentName=name,
            type="MANAGED",
            state=state,
            serviceRole=role_arn,
            computeResources={
                "type": "FARGATE",
                "maxvCpus": max_vcpus,
                "subnets": subnets,
                "securityGroupIds": [sg],
            },
            tags=_MANAGED_TAGS,
        )

    if role_just_created:
        # Freshly-created IAM roles are not instantly visible to Batch; bound the
        # wait to that specific cause instead of sleeping unconditionally.
        deadline = time.monotonic() + 60
        last_exc: Exception | None = None
        while True:
            try:
                resp = _create()
                break
            except Exception as exc:
                last_exc = exc
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        "create_compute_environment did not accept the freshly-created "
                        f"AWSServiceRoleForBatch within 60s: {last_exc}"
                    ) from last_exc
                time.sleep(3)
    else:
        resp = _create()
    ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, name))
    return name, resp["computeEnvironmentArn"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MANAGED/FARGATE CE reaches VALID and echoes back its computeResources exactly.

    It reports the created ARN, the given subnets and security group, and a backing ecsClusterArn.
    """
    bat = ctx.client("batch")
    subnets, sg = _default_vpc_networking(ctx)
    name, arn = _create_fargate_ce(ctx, bat, max_vcpus=4)

    ce = _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=180, interval_s=5)
    assert ce["status"] == "VALID", f"expected VALID, got {ce['status']!r}: {ce.get('statusReason')}"
    assert ce["type"] == "MANAGED"
    assert ce["state"] == "ENABLED"
    assert ce["computeEnvironmentArn"] == arn

    cr = ce["computeResources"]
    assert cr["type"] == "FARGATE"
    assert cr["maxvCpus"] == 4
    assert set(cr["subnets"]) == set(subnets)
    assert cr["securityGroupIds"] == [sg]
    # Batch provisions a backing ECS cluster for every MANAGED compute environment.
    assert ce.get("ecsClusterArn"), "expected a backing ecsClusterArn for a MANAGED CE"


def _wait_compute_environment_gone(batch, name, timeout_s=300.0, interval_s=5.0):
    """Wait until a deleted compute environment is gone; the delete is asynchronous and needs the
    service role until it completes, so a later cleanup must not delete the role first."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
