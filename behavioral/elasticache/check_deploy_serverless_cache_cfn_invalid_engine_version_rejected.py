"""deploy-serverless-cache-cfn-invalid-engine-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-serverless-cache-cfn-invalid-engine-version-rejected"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServerlessCache with a bogus MajorEngineVersion is rejected with
    InvalidParameterCombination; a CFN stack with that template rolls back without creating the
    cache, while a sibling stack with a valid template deploys and becomes available."""
    ec = ctx.client("elasticache")
    cfn = ctx.client("cloudformation")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_test_security_group(ctx, vpc_id)

    bad_name = ctx.unique_name("sim2real-sc-bad-")
    ctx.on_cleanup(lambda: _delete_serverless_cache_if_present(ctx, bad_name))
    code, message = _error(
        lambda: ec.create_serverless_cache(
            ServerlessCacheName=bad_name, Engine="redis", MajorEngineVersion="999.999", SubnetIds=ctx.network().subnet_ids[:3]
        )
    )
    # Real AWS rejects this as an incompatible parameter combination (Engine=redis with a
    # nonexistent MajorEngineVersion), not the InvalidParameterValueException documented.
    assert code == "InvalidParameterCombination", code
    assert message == "Specified engine does not support major engine version (999.999).", message
    # The direct call must not have left anything behind.
    _assert_cache_absent(ec, bad_name)

    bad_stack = ctx.unique_name("sim2real-ec-sc-bad-stack-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_serverless_template(bad_name, subnet_ids, sg_id, major_engine_version="999.999"),
        OnFailure="ROLLBACK",
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, bad_stack))
    status = _wait_stack_status(ctx, bad_stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE"}, timeout_s=900.0)
    assert status == "ROLLBACK_COMPLETE", f"expected rollback, stack ended in {status}"
    _assert_cache_absent(ec, bad_name)

    good_name = ctx.unique_name("sim2real-sc-good-")
    good_stack = ctx.unique_name("sim2real-ec-sc-good-stack-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_serverless_template(good_name, subnet_ids, sg_id, major_engine_version=None),
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, good_stack))
    status = _wait_stack_status(ctx, good_stack, {"CREATE_COMPLETE"}, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", f"positive control stack ended in {status}"
    desc = ec.describe_serverless_caches(ServerlessCacheName=good_name)["ServerlessCaches"][0]
    # Real AWS returns the lowercase wire value ("available"), not the uppercase enum name the
    # API reference documents.
    assert desc["Status"] == "available", desc["Status"]


def _serverless_template(name: str, subnet_ids: list[str], sg_id: str, major_engine_version: str | None) -> str:
    props = {
        "ServerlessCacheName": name,
        "Engine": "redis",
        "SubnetIds": subnet_ids,
        "SecurityGroupIds": [sg_id],
    }
    if major_engine_version is not None:
        props["MajorEngineVersion"] = major_engine_version
    return json.dumps({"Resources": {"ServerlessCache": {"Type": "AWS::ElastiCache::ServerlessCache", "Properties": props}}})


def _default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        # No shared network: fall back to any VPC in the account/region rather than failing a check
        # that has nothing to do with default-VPC semantics specifically.
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < 2:
        raise AssertionError(f"VPC {vpc_id} has fewer than 2 subnets available for the serverless cache")
    return vpc_id, [s["SubnetId"] for s in subnets[:2]]


def _create_test_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ec-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elasticache behavioral test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _wait_stack_status(
    ctx, stack_name: str, target_statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 15.0
) -> str:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError" and "DELETE_COMPLETE" in target_statuses:
                return "DELETE_COMPLETE"
            raise
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
    _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"}, timeout_s=900.0)


def _assert_cache_absent(ec, name: str) -> None:
    code, message = _error(lambda: ec.describe_serverless_caches(ServerlessCacheName=name))
    assert code == "ServerlessCacheNotFoundFault", code
    assert message == f"Serverless cache with name {name} not found.", message


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_serverless_cache_if_present(ctx, name: str) -> None:
    ec = ctx.client("elasticache")
    try:
        ec.delete_serverless_cache(ServerlessCacheName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServerlessCacheNotFoundFault":
            raise



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
