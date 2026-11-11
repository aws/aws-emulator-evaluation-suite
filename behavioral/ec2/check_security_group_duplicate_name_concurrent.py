"""security-group-duplicate-name-concurrent."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-duplicate-name-concurrent"
GROUP = 'concurrency'
SERVICES = ['ec2']


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateSecurityGroup calls with the same name+VPC: exactly one succeeds, rest fail with InvalidGroup.Duplicate."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + _budget_s(ctx, 60)
    state = None
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            break
        time.sleep(2)
    if state != "available" and _budget_spent(ctx):
        raise TimeoutError(f"vpc {vpc_id} reaching available: the run budget ended first; not graded")
    assert state == "available", f"vpc {vpc_id} did not reach available within 60s, last state {state!r}"

    name = ctx.unique_name("sim2real-behav-sg-dup-")
    # No client retries for the racers: a retried create whose first attempt landed would read
    # back as InvalidGroup.Duplicate and hide the winner.
    racer = ctx.client("ec2", config=Config(retries={"total_max_attempts": 1}))

    def create():
        return racer.create_security_group(
            GroupName=name, Description="dup race", VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )["GroupId"]

    # Fire N creates at once; capture each call's return value OR its exception in
    # submission order so we can assert on the distribution of outcomes.
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(create) for _ in range(5)]
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001 — captured for assertion
                results.append(exc)

    n_ok = sum(1 for r in results if not isinstance(r, BaseException))
    assert n_ok == 1, f"expected exactly one winner, got {n_ok} successes: {results}"

    winners = [r for r in results if not isinstance(r, BaseException)]
    winner = winners[0]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=winner))

    error_codes = []
    for r in results:
        if isinstance(r, ClientError):
            error_codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            error_codes.append(type(r).__name__)
    assert len(error_codes) == 4, f"expected 4 losers, got {error_codes}"
    assert all(c == "InvalidGroup.Duplicate" for c in error_codes), (
        f"expected all losers to be InvalidGroup.Duplicate, got {error_codes}"
    )
    expected = f"The security group '{name}' already exists for VPC '{vpc_id}'"
    for r in results:
        if isinstance(r, ClientError):
            message = r.response.get("Error", {}).get("Message")
            assert message == expected, f"expected every loser's message to be {expected!r}, got {message!r}"

    # Independent read at the destination: exactly one group with this name+VPC exists, and it
    # is the racer that CreateSecurityGroup told us won — not just a self-report from the
    # mutating calls themselves.
    surviving = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [name]}]
    )["SecurityGroups"]
    assert len(surviving) == 1, (
        f"expected exactly one security group named {name!r} in {vpc_id}, found {len(surviving)}: {surviving}"
    )
    assert surviving[0]["GroupId"] == winner, (
        f"expected the sole survivor to be the reported winner {winner}, got {surviving[0]['GroupId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
