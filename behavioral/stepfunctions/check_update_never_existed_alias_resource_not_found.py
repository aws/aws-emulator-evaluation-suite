"""update-never-existed-alias-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-never-existed-alias-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity",):
            raise


def _error(fn):
    """The AWS error `fn` raised, as {"Code", "Status", "Message"}. An unexpected success raises,
    so a target that accepts what AWS refuses can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {"Code": err.get("Code"), "Status": status, "Message": err.get("Message") or ""}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias on an alias ARN that never existed, under a real state machine,
    fails with ResourceNotFound, HTTP 400, and a generic message that does not name the ARN.
    """
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _create_sfn_role(ctx))

    # Positive control: a real alias, on the real state machine, describes cleanly — so a
    # ResourceNotFound below cannot be read as "aliases are unsupported at all".
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    real_alias_name = ctx.unique_name("sim2real-behav-alias-")
    real_alias_arn = sfn.create_state_machine_alias(
        name=real_alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=real_alias_arn))
    )
    control = sfn.describe_state_machine_alias(stateMachineAliasArn=real_alias_arn)
    assert control["name"] == real_alias_name, (
        f"expected {real_alias_name!r}, got {control['name']!r}"
    )

    # The alias ARN under test names a well-formed alias of the real state machine that this
    # check never created, so a ResourceNotFound here is unambiguously about the alias itself.
    never_existed_arn = f"{sm_arn}:{ctx.unique_name('sim2real-behav-never-existed-')}"

    update_err = _error(
        lambda: sfn.update_state_machine_alias(
            stateMachineAliasArn=never_existed_arn,
            routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
        )
    )
    expected_update = {
        "Code": "ResourceNotFound",
        "Status": 400,
        "Message": "Request references a resource that does not exist.",
    }
    assert update_err == expected_update, (
        f"UpdateStateMachineAlias on a never-existed alias: expected {expected_update}, "
        f"got {update_err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
