"""concurrent-update-compute-environment-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-compute-environment-conflict"
GROUP = "concurrency"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateComputeEnvironment calls setting different maxvCpus resolve atomically.

    At least one succeeds and the CE settles VALID with exactly one of the two submitted values.
    """
    batch = ctx.client("batch")
    vpc_id, subnets = _default_subnets(ctx)
    sg_id = _default_sg(ctx, vpc_id)

    ce_name = ctx.unique_name("sim2real-batch-ce-")
    _create_fargate_ce(ctx, ce_name, 2, subnets, sg_id)

    outcomes: dict[str, Any] = {}

    def _update(max_vcpus: int, key: str) -> None:
        try:
            batch.update_compute_environment(
                computeEnvironment=ce_name,
                computeResources={"maxvCpus": max_vcpus},
            )
            outcomes[key] = "ok"
        except ClientError as e:
            outcomes[key] = e.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, 4, "a"), pool.submit(_update, 8, "b")]
        for f in futures:
            f.result()

    assert "ok" in outcomes.values(), f"neither concurrent UpdateComputeEnvironment call succeeded: {outcomes}"

    final = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda ce: ce["status"] == "VALID",
        timeout_s=180,
        interval_s=5,
    )
    max_vcpus = final["computeResources"]["maxvCpus"]
    assert max_vcpus in (4, 8), f"maxvCpus converged to an unexpected torn value: {max_vcpus}"
    assert final["status"] == "VALID", f"expected final status VALID, got {final['status']} ({final.get('statusReason')})"
    assert final["computeEnvironmentName"] == ce_name, (
        f"expected computeEnvironmentName {ce_name}, got {final['computeEnvironmentName']}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_subnets(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:

        raise AssertionError("shared network has no subnets")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _default_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return sgs[0]["GroupId"]


def _create_fargate_ce(ctx, name: str, max_vcpus: int, subnets: list, sg_id: str) -> str:
    batch = ctx.client("batch")
    batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg_id],
        },
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _drain_and_delete_ce(ctx, name))
    ce = _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
        lambda ce: ce["status"] in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=5,
    )
    assert ce["status"] == "VALID", f"compute environment failed to validate: {ce.get('statusReason')}"
    return ce["computeEnvironmentArn"]


def _drain_and_delete_ce(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
            lambda ce: ce["status"] == "VALID",
            timeout_s=120,
            interval_s=5,
        )
        _delete_compute_environment_and_wait(batch, name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise



def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    batch.delete_compute_environment(computeEnvironment=name)
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
