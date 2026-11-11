"""tag-resources-nonexistent-state-machine-rejected-per-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-state-machine-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi", "stepfunctions"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch of one live and one absent state machine succeeds as a 200, tags the
    live one, and reports the absent one in FailedResourcesMap with Step Functions' own
    ResourceNotFound -- never silently accepted and never a whole-batch failure.
    """
    sfn = ctx.client("stepfunctions")
    rgt = ctx.client("resourcegroupstaggingapi")
    account = ctx.account
    key = ctx.unique_name("sim2real-behav-part-")

    role_arn = _create_sfn_role(ctx)
    live_arn = _create_state_machine(ctx, role_arn)

    ghost_arn = f"arn:aws:states:{ctx.region}:{account}:stateMachine:{ctx.unique_name('sim2real-behav-ghost-')}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent state "
        f"machine {ghost_arn!r} -- the live state machine {live_arn!r} must not fail and the "
        f"absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "ResourceNotFound", (
        f"the per-resource ErrorCode for an absent state machine was {detail['ErrorCode']!r}, "
        f"expected Step Functions' own ResourceNotFound"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected = f"Resource not found: '{ghost_arn}'"
    assert detail["ErrorMessage"] == expected, (
        f"the per-resource ErrorMessage was {detail['ErrorMessage']!r}, expected {expected!r}"
    )

    native_tags = _poll_until(
        lambda: {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=live_arn)["tags"]},
        lambda m: m.get(key) == "partial",
        timeout_s=180.0,
    )
    assert native_tags.get(key) == "partial", (
        f"the live state machine {live_arn!r} never received {key}=partial (saw {native_tags!r}) "
        f"-- a partial failure must still apply the tags that succeeded"
    )


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real " + CHECK, Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = json.dumps({
        "StartAt": "Done",
        "States": {"Done": {"Type": "Pass", "End": True}},
    })
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
