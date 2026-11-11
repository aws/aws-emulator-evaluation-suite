"""cfn-rds-db-subnet-group-single-az-rejected-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-db-subnet-group-single-az-rejected-negative"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "ec2", "rds"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB subnet group whose subnets share one AZ fails the stack with RDS's own error, rolls the
    VPC back, and leaves no group; the two-AZ version produces a group RDS and EC2 agree about.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    template = (DEPLOYMENTS / "rds-subnet-group.yaml").read_text()

    # ---- negative leg: both subnets in one AZ ----
    bad_group = _xname(ctx, "dbsg-bad")
    ctx.on_cleanup(lambda: _delete_subnet_group_if_present(rds, bad_group))
    failed = _deploy_cfn_expect_terminal(
        ctx,
        template,
        parameters={"SubnetGroupName": bad_group, "SingleAz": "true"},
        timeout_s=900.0,
    )
    assert failed["status"] == "ROLLBACK_COMPLETE", (
        f"stack ended in {failed['status']}; a resource that cannot be created must roll the "
        "stack back to ROLLBACK_COMPLETE"
    )

    events = _stack_resource_events(cfn, failed["stack_name"])
    group_events = [e for e in events if e.get("LogicalResourceId") == "SubnetGroup"]
    assert any(e["ResourceStatus"] == "CREATE_FAILED" for e in group_events), (
        "the DB subnet group was not the resource that failed: "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]}"
    )
    reasons = " ".join(e.get("ResourceStatusReason", "") for e in group_events)
    # The CREATE_FAILED event wraps RDS's error MESSAGE, never its exception code, and embeds a
    # per-call Request ID and RequestToken, so its stable parts are asserted here and the exception
    # code is asserted against RDS directly below.
    assert "(Service: Rds" in reasons, (
        "the stack event must attribute the failure to RDS, not to CloudFormation's own "
        f"validation, got {reasons!r}"
    )
    assert "Availability Zone (AZ) coverage requirement" in reasons, (
        f"the stack event must name AZ coverage as the reason, got {reasons!r}"
    )
    assert "at least 2 AZs" in reasons, (
        f"the stack event must state the minimum AZ count RDS requires, got {reasons!r}"
    )
    assert "HandlerErrorCode: InvalidRequest" in reasons, (
        f"a rejected input must be classified InvalidRequest, not a retryable/internal handler "
        f"error, got {reasons!r}"
    )

    # The failing resource must not exist as far as RDS is concerned.
    _expect_client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=bad_group),
        {"DBSubnetGroupNotFoundFault"},
        f"describe_db_subnet_groups {bad_group} after rollback",
        message=f"DB Subnet group '{bad_group}' not found.",
    )

    # Rollback must also have removed the resources that DID succeed before the failure.
    vpc_events = [e for e in events if e.get("LogicalResourceId") == "Vpc"]
    created_vpcs = [
        e["PhysicalResourceId"]
        for e in vpc_events
        if e["ResourceStatus"] == "CREATE_COMPLETE" and e.get("PhysicalResourceId")
    ]
    assert created_vpcs, (
        f"the VPC never reached CREATE_COMPLETE, so this run did not exercise rollback of a "
        f"partially created stack: {[(e['ResourceStatus']) for e in vpc_events]}"
    )
    _poll_for_client_error(
        lambda: ec2.describe_vpcs(VpcIds=[created_vpcs[0]]),
        {"InvalidVpcID.NotFound"},
        f"describe_vpcs {created_vpcs[0]} after rollback",
        message=f"The vpc ID '{created_vpcs[0]}' does not exist",
        timeout_s=180.0,
    )

    # ---- control leg: the same template with two distinct AZs ----
    good_group = _xname(ctx, "dbsg-ok")
    ctx.on_cleanup(lambda: _delete_subnet_group_if_present(rds, good_group))
    result = _deploy_cfn(
        ctx,
        template,
        parameters={"SubnetGroupName": good_group, "SingleAz": "false"},
        timeout_s=900.0,
    )
    outputs = _outputs(result)
    assert outputs["SubnetGroupNameOut"] == good_group, outputs

    group = rds.describe_db_subnet_groups(DBSubnetGroupName=good_group)[
        "DBSubnetGroups"
    ][0]
    assert group["VpcId"] == outputs["VpcId"], (
        f"RDS reports the group in VPC {group['VpcId']!r}, CloudFormation created "
        f"{outputs['VpcId']!r}"
    )

    subnet_ids = [outputs["SubnetAId"], outputs["SubnetBId"]]
    ec2_zones = {
        s["SubnetId"]: s["AvailabilityZone"]
        for s in ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    }
    assert len(set(ec2_zones.values())) == 2, (
        f"!GetAZs must place the two subnets in different zones, got {ec2_zones}"
    )
    rds_zones = {
        s["SubnetIdentifier"]: s["SubnetAvailabilityZone"]["Name"]
        for s in group["Subnets"]
    }
    assert rds_zones == ec2_zones, (
        f"RDS reports subnet zones {rds_zones}, EC2 reports {ec2_zones}; the DB subnet group must "
        "carry the real zone of each subnet"
    )

    # ---- the same rejection, straight from RDS ----
    # Calling RDS directly proves the stack message wraps RDS's own typed rejection. The extra
    # subnet shares SubnetA's zone, so the pair differs from the control only in AZ spread; it is
    # registered after the stack's teardown so LIFO removes it before the VPC.
    extra_subnet = ec2.create_subnet(
        VpcId=outputs["VpcId"],
        CidrBlock="10.31.3.0/24",
        AvailabilityZone=ec2_zones[outputs["SubnetAId"]],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _xsvc_tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_if_present(ec2, extra_subnet))
    direct_group = _xname(ctx, "dbsg-direct")
    ctx.on_cleanup(lambda: _delete_subnet_group_if_present(rds, direct_group))
    _expect_client_error(
        lambda: rds.create_db_subnet_group(
            DBSubnetGroupName=direct_group,
            DBSubnetGroupDescription="sim2real single-AZ rejection, straight from RDS",
            SubnetIds=[outputs["SubnetAId"], extra_subnet],
            Tags=_xsvc_tags_kv(),
        ),
        {"DBSubnetGroupDoesNotCoverEnoughAZs"},
        f"create_db_subnet_group {direct_group} over two subnets in one AZ",
        message=(
            "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
            f"Current AZ coverage: {ec2_zones[outputs['SubnetAId']]}. "
            "Add subnets to cover at least 2 AZs."
        ),
    )
    # ...and the rejected group must not exist.
    _expect_client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=direct_group),
        {"DBSubnetGroupNotFoundFault"},
        f"describe_db_subnet_groups {direct_group} after the direct rejection",
        message=f"DB Subnet group '{direct_group}' not found.",
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _expect_client_error(fn, codes, description, *, message):
    """Require fn() to raise ClientError with an Error.Code in codes and exactly `message`;
    return the code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        got = exc.response.get("Error", {}).get("Message")
        assert got == message, f"{description}: expected message {message!r}, got {got!r}"
        return code
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _poll_for_client_error(fn, codes, description, *, message, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises ClientError with a code in codes (deletions are eventual); the
    error must carry exactly `message`."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in codes:
                got = exc.response.get("Error", {}).get("Message")
                assert got == message, f"{description}: expected message {message!r}, got {got!r}"
                return code
            raise AssertionError(
                f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected one of "
                f"{sorted(codes)}"
            )
        time.sleep(interval_s)


def _stack_resource_events(cfn, stack_name: str) -> list[dict[str, Any]]:
    """Every resource event for a stack, oldest first."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _delete_subnet_group_if_present(rds, name: str) -> None:
    """Best-effort DB subnet group teardown; already-deleted is not an error."""
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {
            "DBSubnetGroupNotFoundFault",
            "DBSubnetGroupNotFound",
        }:
            raise


def _delete_subnet_if_present(ec2, subnet_id: str) -> None:
    """Best-effort subnet teardown; already-deleted is not an error."""
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidSubnetID.NotFound":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; on_cleanup swallows errors)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _create_stack(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None
) -> str:
    """create_stack with the xsvc naming/tagging conventions and teardown registered up front."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=600.0))
    return name


def _deploy_cfn_expect_terminal(
    ctx, template, *, parameters=None, capabilities=None, timeout_s=600.0
) -> dict[str, Any]:
    """Deploy a stack expected to FAIL: poll to any terminal create status and return it."""
    cfn = ctx.client("cloudformation")
    name = _create_stack(
        ctx, template, parameters=parameters, capabilities=capabilities
    )
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "CREATE_COMPLETE",
            "CREATE_FAILED",
            "ROLLBACK_COMPLETE",
            "ROLLBACK_FAILED",
        },
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    return {"stack_name": name, "status": status}


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
