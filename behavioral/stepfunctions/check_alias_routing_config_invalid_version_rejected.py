"""alias-routing-config-invalid-version-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-routing-config-invalid-version-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias routing to a never-published version ARN fails ResourceNotFound,
    while an alias to the published version succeeds and is the only alias listed."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _SIMPLE_DEFINITION)
    sfn = ctx.client("stepfunctions")

    # The next ordinal after the only published version is a well-formed but unpublished target.
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)))
    bogus_version_arn = f"{sm_arn}:2"

    good_name = ctx.unique_name("sim2real-alias-good-")
    good_alias_arn = sfn.create_state_machine_alias(
        name=good_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=good_alias_arn)))
    good_desc_name = sfn.describe_state_machine_alias(stateMachineAliasArn=good_alias_arn)["name"]
    assert good_desc_name == good_name, f"positive control: expected {good_name!r}, got {good_desc_name!r}"

    err = _error(
        lambda: sfn.create_state_machine_alias(
            name=ctx.unique_name("sim2real-alias-bogus-"),
            routingConfiguration=[{"stateMachineVersionArn": bogus_version_arn, "weight": 100}],
        )
    )
    expected = {
        "Code": "ResourceNotFound",
        "Message": "Routing configuration must contain state machine version ARNs that already exist.",
    }
    assert err == expected, f"expected {expected}, got {err}"

    # ListStateMachineAliases items carry only stateMachineAliasArn/creationDate, no name.
    aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_arn)["stateMachineAliases"]
    arns = [a["stateMachineAliasArn"] for a in aliases]
    assert arns == [good_alias_arn], f"expected only {good_alias_arn!r}, got {arns}"


_SIMPLE_DEFINITION = {
    "Comment": "simple",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "ok", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn() and return its error as {"Code", "Message"}; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
