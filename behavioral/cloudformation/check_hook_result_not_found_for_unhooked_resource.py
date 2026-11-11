"""hook-result-not-found-for-unhooked-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-result-not-found-for-unhooked-resource"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListHookResults with TargetType=RESOURCE and a stack resource's PhysicalResourceId fails with
    ValidationError "Invalid TargetType: RESOURCE" (only CHANGE_SET and CLOUD_CONTROL are supported
    filters), while an unfiltered ListHookResults returns HookResults."""
    cfn = ctx.client("cloudformation")

    # Positive control: the unfiltered form is a supported combination and must succeed
    # for a healthy account/target, ruling out "everything about ListHookResults 500s".
    control = cfn.list_hook_results()
    assert "HookResults" in control, f"expected a HookResults key on the control call, got {control}"

    stack_name = ctx.unique_name("sim2real-hookres-rt-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status}"

    physical_id = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Topic")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    try:
        results = cfn.list_hook_results(TargetType="RESOURCE", TargetId=physical_id)
    except ClientError as exc:
        err = exc.response["Error"]
        # RESOURCE is not a supported TargetType filter for ListHookResults (only
        # CHANGE_SET and CLOUD_CONTROL are); CloudFormation rejects it whether or not
        # the addressed resource has had Hook activity.
        assert err.get("Code") == "ValidationError", f"expected ValidationError, got {err}"
        assert err.get("Message") == "Invalid TargetType: RESOURCE", (
            f"expected message 'Invalid TargetType: RESOURCE', got {err}"
        )
    else:
        raise AssertionError(
            "expected ListHookResults(TargetType=RESOURCE) to be rejected as an "
            f"unsupported filter, got a 200 with {results}"
        )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
