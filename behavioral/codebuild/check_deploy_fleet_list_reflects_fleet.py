"""deploy-fleet-list-reflects-fleet."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-fleet-list-reflects-fleet"
GROUP = "deploy"
SERVICES = ["codebuild"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  FleetName:
    Type: String
Resources:
  Fleet:
    Type: AWS::CodeBuild::Fleet
    Properties:
      Name: !Ref FleetName
      BaseCapacity: 1
      EnvironmentType: LINUX_CONTAINER
      ComputeType: BUILD_GENERAL1_SMALL
Outputs:
  FleetArn:
    Value: !GetAtt Fleet.Arn
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A reserved-capacity compute fleet deployed via CloudFormation is discoverable
    through ListFleets and BatchGetFleets with matching capacity/environment/compute
    attributes, and reaches ACTIVE status (not just stack CREATE_COMPLETE)."""
    fleet_name = ctx.unique_name("sim2real-behav-fleet-")
    outputs = _deploy_cfn(ctx, _TEMPLATE, {"FleetName": fleet_name})
    fleet_arn = outputs["FleetArn"]

    codebuild = ctx.client("codebuild")

    arns = _poll_until(
        lambda: codebuild.list_fleets()["fleets"],
        lambda arns: fleet_arn in arns,
        timeout_s=120,
        interval_s=5,
    )
    assert fleet_arn in arns, f"ListFleets never surfaced {fleet_arn!r}: {arns!r}"

    fleet = _poll_until(
        lambda: codebuild.batch_get_fleets(names=[fleet_name])["fleets"][0],
        lambda f: f["status"]["statusCode"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert fleet["status"]["statusCode"] == "ACTIVE", f"fleet did not become ACTIVE: {fleet}"
    assert fleet["arn"] == fleet_arn, f"BatchGetFleets arn {fleet['arn']!r} != stack output {fleet_arn!r}"
    assert fleet["baseCapacity"] == 1, f"expected baseCapacity=1, got {fleet['baseCapacity']!r}"
    assert fleet["environmentType"] == "LINUX_CONTAINER", (
        f"expected environmentType=LINUX_CONTAINER, got {fleet['environmentType']!r}"
    )
    assert fleet["computeType"] == "BUILD_GENERAL1_SMALL", (
        f"expected computeType=BUILD_GENERAL1_SMALL, got {fleet['computeType']!r}"
    )

    # BatchGetFleets' fleetsNotFound only ever names ARN-shaped identifiers; a bare
    # nonexistent fleet *name* is silently dropped from both fleets and fleetsNotFound
    # (measured on real AWS — not documented). So the not-found leg uses a fabricated
    # but well-formed ARN, mixed with the real fleet queried by plain name.
    nonexistent_arn = fleet_arn.rsplit(":", 1)[0] + ":00000000-0000-0000-0000-000000000000"
    mixed = codebuild.batch_get_fleets(names=[fleet_name, nonexistent_arn])
    assert [f["name"] for f in mixed["fleets"]] == [fleet_name], (
        f"expected only {fleet_name!r} in fleets, got {[f.get('name') for f in mixed['fleets']]!r}"
    )
    assert mixed["fleetsNotFound"] == [nonexistent_arn], (
        f"expected fleetsNotFound=[{nonexistent_arn!r}], got {mixed['fleetsNotFound']!r}"
    )


# ===== helpers =====


def _deploy_cfn(ctx: Any, template_body: str, parameters: dict) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        # Bounded to fit the suite's cleanup budget.
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 400})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
