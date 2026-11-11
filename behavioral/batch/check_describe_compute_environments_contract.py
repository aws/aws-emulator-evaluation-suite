"""describe-compute-environments-contract."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-compute-environments-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeComputeEnvironments returns the created environment's real shape and rejects a bogus nextToken."""
    batch = ctx.client("batch")
    subnet_ids, sg_id = _get_default_subnets_and_sg(ctx)
    name = ctx.unique_name("sim2real-batch-ce-")

    ce_arn = batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 8,
            "subnets": subnet_ids,
            "securityGroupIds": [sg_id],
        },
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-ce"},
    )["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _force_delete_ce(batch, name))

    env = _poll_until(
        lambda: _describe_ce(batch, name),
        lambda e: e is not None and e["status"] in ("VALID", "INVALID"),
        timeout_s=180,
    )
    assert env["status"] == "VALID", f"compute environment failed to validate: {env}"
    assert env["type"] == "MANAGED", f"expected type MANAGED, got {env['type']!r}"
    assert env["state"] == "ENABLED", f"expected state ENABLED, got {env['state']!r}"
    assert env["computeResources"]["type"] == "FARGATE", (
        f"expected computeResources.type FARGATE, got {env['computeResources']['type']!r}"
    )
    assert env["computeResources"]["maxvCpus"] == 8, (
        f"expected maxvCpus 8, got {env['computeResources']['maxvCpus']!r}"
    )
    assert sorted(env["computeResources"]["subnets"]) == sorted(subnet_ids), (
        f"expected subnets {sorted(subnet_ids)}, got {sorted(env['computeResources']['subnets'])}"
    )

    # Negative: an invalid pagination token is rejected distinctly from a filter mismatch.
    code, message = _error_code(lambda: batch.describe_compute_environments(nextToken="not-a-real-token-!!"))
    assert code == "ClientException", f"expected ClientException for invalid nextToken, got {code}"
    assert message == "Error processing next token", (
        f"expected message 'Error processing next token', got {message!r}"
    )

    # The delete this check's cleanup would otherwise perform silently: prove gone and unusable.
    batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
    _poll_until(
        lambda: _describe_ce(batch, name),
        lambda e: e is not None and e["state"] == "DISABLED" and e["status"] == "VALID",
        timeout_s=180,
    )
    batch.delete_compute_environment(computeEnvironment=name)
    gone = _poll_until(
        lambda: _describe_ce(batch, name),
        lambda e: e is None,
        timeout_s=180,
    )
    assert gone is None, "compute environment still describable after successful delete"

    post_delete_code, post_delete_message = _error_code(
        lambda: batch.update_compute_environment(computeEnvironment=name, state="ENABLED")
    )
    assert post_delete_code == "ClientException", (
        f"expected ClientException updating a deleted CE, got {post_delete_code}"
    )
    expected_dead = f"{ce_arn} does not exist"
    assert post_delete_message == expected_dead, (
        f"expected message {expected_dead!r}, got {post_delete_message!r}"
    )


# ===== helpers =====

def _get_default_subnets_and_sg(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available for compute environment networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return [s["SubnetId"] for s in subnets[:2]], sgs[0]["GroupId"]


def _describe_ce(batch: Any, name: str) -> dict[str, Any] | None:
    envs = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
    return envs[0] if envs else None


def _poll_until(probe, predicate, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _force_delete_ce(batch: Any, name: str) -> None:
    if _describe_ce(batch, name) is None:
        return
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    # DeleteComputeEnvironment is refused (ClientException) while the DISABLED update settles.
    deadline = time.monotonic() + 180
    while True:
        try:
            batch.delete_compute_environment(computeEnvironment=name)
            return
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
