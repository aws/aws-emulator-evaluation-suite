"""create-state-machine-alias-description-exceeds-length-limit-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-alias-description-exceeds-length-limit-rejected"
GROUP = "aliases"
SERVICES = ["stepfunctions", "iam"]

_MAX_DESCRIPTION_LEN = 256

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_PASS_DEFINITION = json.dumps({
    "StartAt": "Done",
    "States": {"Done": {"Type": "Succeed"}},
})


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected CreateStateMachineAlias to be refused, but it succeeded: {result!r}"
    )


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-aliasdesc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_published_state_machine(ctx, sfn, role_arn: str) -> str:
    """Creates a state machine and publishes version 1; returns the version ARN a routing
    configuration can target."""
    name = ctx.unique_name("sim2real-behav-aliasdesc-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias with a 257-character description fails with ValidationException
    and the exact length-constraint message and creates nothing, while a description of
    exactly 256 characters is accepted and describable."""
    sfn = ctx.client("stepfunctions")
    sfn_raw = ctx.client("stepfunctions", config=Config(parameter_validation=False))
    role_arn = _create_role(ctx)
    version_arn = _create_published_state_machine(ctx, sfn, role_arn)
    routing = [{"stateMachineVersionArn": version_arn, "weight": 100}]

    too_long = "d" * (_MAX_DESCRIPTION_LEN + 1)
    bad_name = ctx.unique_name("sim2real-behav-aliasdesc-bad-")
    code, message = _error(lambda: sfn_raw.create_state_machine_alias(
        name=bad_name, description=too_long, routingConfiguration=routing,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = (
        f"1 validation error detected: Value at 'description' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_MAX_DESCRIPTION_LEN}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sm_arn = version_arn.rsplit(":", 1)[0]
    names, kwargs = set(), {"stateMachineArn": sm_arn}
    while True:
        page = sfn.list_state_machine_aliases(**kwargs)
        names.update(a["stateMachineAliasArn"].rsplit(":", 1)[-1] for a in page["stateMachineAliases"])
        token = page.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    assert bad_name not in names, f"a refused alias named {bad_name!r} is listed"

    at_limit = "d" * _MAX_DESCRIPTION_LEN
    good_name = ctx.unique_name("sim2real-behav-aliasdesc-ok-")
    alias_arn = sfn.create_state_machine_alias(
        name=good_name, description=at_limit, routingConfiguration=routing,
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))
    described = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert described["description"] == at_limit, (
        f"DescribeStateMachineAlias returned a description of length "
        f"{len(described['description'])}, expected {_MAX_DESCRIPTION_LEN}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
