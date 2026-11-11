"""ce-managed-fargate-missing-subnets-fails."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ce-managed-fargate-missing-subnets-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _err_code(fn):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, so accepting input AWS refuses is never reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


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


def _wait_ce_status(bat, name, statuses, timeout_s=45, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (valid for MANAGED CEs). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
        return resp["Role"]["Arn"]
    except Exception as exc:
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc


def _create_ce_retrying_role_propagation(bat, **kwargs):
    """create_compute_environment, retrying while the SLR is not yet assumable by Batch."""
    last_exc = None
    for attempt in range(8):
        try:
            return bat.create_compute_environment(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            transient = (
                "cannot be assumed" in msg
                or "not authorized to perform: sts:assumerole" in msg
                or "does not have permission" in msg
            )
            if not transient or attempt == 7:
                raise
            last_exc = exc
            time.sleep(5)
    raise last_exc  # type: ignore[misc]  # pragma: no cover - loop always returns or raises


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from the run's shared network (MANAGED CEs)."""
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
    return subnet_ids[:3], sgs[0]["GroupId"]


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it (best-effort).

    Batch refuses to delete a CE still in CREATING, so the wait is required, not
    cosmetic -- bounded well under the 60s ctx.on_cleanup budget.
    """
    _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=30, interval_s=3)
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _wait_compute_environment_gone(bat, name)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A MANAGED FARGATE compute environment with no subnets is refused at create time.

    The identical shape with real subnets is accepted first, so the refusal is due to the subnets.
    """
    bat = ctx.client("batch")
    role = _service_linked_role_arn(ctx)
    subnets, sg = _default_vpc_networking(ctx)

    # Positive control: the same MANAGED/FARGATE shape, with real subnets, is accepted.
    ok_name = ctx.unique_name("sim2real-behav-ce-fg-ok-")
    ok = _create_ce_retrying_role_propagation(
        bat,
        computeEnvironmentName=ok_name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 16,
            "subnets": subnets,
            "securityGroupIds": [sg],
        },
        serviceRole=role,
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, ok_name))
    assert ok.get("computeEnvironmentArn"), (
        "positive control: a MANAGED FARGATE CE with real subnets must be accepted"
    )
    # Settle here rather than in cleanup: a FARGATE CE's ECS cluster often takes over 60s to
    # provision, longer than the cleanup budget.
    settled = _wait_ce_status(bat, ok_name, {"VALID", "INVALID"}, timeout_s=200, interval_s=5)
    assert settled is not None, "positive control CE must be independently readable after creation"

    bad_name = ctx.unique_name("sim2real-behav-ce-fg-bad-")

    def _try_bad_create():
        resp = bat.create_compute_environment(
            computeEnvironmentName=bad_name,
            type="MANAGED",
            state="ENABLED",
            computeResources={
                "type": "FARGATE",
                "maxvCpus": 16,
                "subnets": [],
                "securityGroupIds": [],
            },
            serviceRole=role,
            tags=_MANAGED_TAGS,
        )
        # A wrongly accepted create must not leak.
        ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, bad_name))
        return resp

    code, message, request_id = _err_code(_try_bad_create)
    assert code == "ClientException", (
        f"expected ClientException for a FARGATE CE with no subnets, got {code!r}"
    )
    # Batch embeds the call's own request id in this message.
    expected_message = (
        "Error executing request, Exception : Resource subnets are required., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ce = _describe_ce(bat, bad_name)
    assert ce is None or ce.get("status") == "DELETED", (
        "rejected CreateComputeEnvironment must not leave a compute environment behind"
    )


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
