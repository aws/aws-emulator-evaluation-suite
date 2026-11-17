"""published-versions-freeze-definition-and-description."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "published-versions-freeze-definition-and-description"
GROUP = "update_versioning"
SERVICES = ["iam", "stepfunctions"]

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_DEF_V1 = {"StartAt": "V1Pass", "States": {"V1Pass": {"Type": "Pass", "End": True}}}
_DEF_V2 = {"StartAt": "V2Pass", "States": {"V2Pass": {"Type": "Pass", "End": True}}}


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    """A states.amazonaws.com-assumable execution role; a Pass-only machine needs no permissions."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _error_code_and_message(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine(publish=true) and UpdateStateMachine(publish=true) each freeze their
    version's definition and versionDescription; the unqualified ARN tracks the latest definition
    with no description; mutating a version ARN is refused with its exact error.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-sfn-pubfreeze-")

    deadline = time.monotonic() + 90.0
    last = None
    created = None
    while time.monotonic() < deadline:
        try:
            created = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_DEF_V1),
                roleArn=role_arn,
                publish=True,
                versionDescription="v1 snapshot",
                tags=[{"key": "sim2real", "value": "1"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        break
    if created is None:
        raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")

    sm_arn = created["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn), "StateMachineDoesNotExist"))
    v1_arn = created["stateMachineVersionArn"]
    assert v1_arn, "expected a stateMachineVersionArn on the publish=true create"
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn), "StateMachineDoesNotExist"))

    update = sfn.update_state_machine(
        stateMachineArn=sm_arn,
        definition=json.dumps(_DEF_V2),
        roleArn=role_arn,
        publish=True,
        versionDescription="v2 snapshot",
    )
    v2_arn = update["stateMachineVersionArn"]
    assert v2_arn, "expected a stateMachineVersionArn on the publish=true update"
    assert v2_arn != v1_arn, f"update's published version {v2_arn!r} must differ from create's {v1_arn!r}"
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2_arn), "StateMachineDoesNotExist"))

    v1_described = sfn.describe_state_machine(stateMachineArn=v1_arn)
    assert json.loads(v1_described["definition"]) == _DEF_V1, (
        f"version 1 must keep its frozen definition, got {v1_described['definition']!r}"
    )
    assert v1_described.get("description") == "v1 snapshot", (
        f"version 1 must keep its description 'v1 snapshot', got {v1_described.get('description')!r}"
    )

    v2_described = sfn.describe_state_machine(stateMachineArn=v2_arn)
    assert json.loads(v2_described["definition"]) == _DEF_V2, (
        f"version 2 must keep its frozen definition, got {v2_described['definition']!r}"
    )
    assert v2_described.get("description") == "v2 snapshot", (
        f"version 2 must keep its description 'v2 snapshot', got {v2_described.get('description')!r}"
    )

    base_described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(base_described["definition"]) == _DEF_V2, (
        f"the unqualified ARN must show the latest definition, got {base_described['definition']!r}"
    )
    assert base_described.get("description") is None, (
        f"the unqualified ARN must carry no description, got {base_described.get('description')!r}"
    )

    versions = _list_versions(sfn, sm_arn)
    assert set(versions) == {v1_arn, v2_arn}, (
        f"ListStateMachineVersions must report exactly the two published versions, got {sorted(versions)!r}"
    )

    code, message = _error_code_and_message(
        lambda: sfn.update_state_machine(stateMachineArn=v1_arn, definition=json.dumps(_DEF_V1))
    )
    _VERSION_ARN_REFUSAL = ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{v1_arn}'")
    assert (code, message) == _VERSION_ARN_REFUSAL, (
        f"expected {_VERSION_ARN_REFUSAL!r} refusing UpdateStateMachine on a version ARN, "
        f"got {(code, message)!r}"
    )

    # Positive control: the same mutation on the unqualified ARN succeeds and is readable back.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V1))
    control_described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(control_described["definition"]) == _DEF_V1, (
        f"positive control: UpdateStateMachine on the unqualified ARN did not take effect, "
        f"got {control_described['definition']!r}"
    )

    # The refused call on the version ARN must not have mutated either version's frozen snapshot.
    v1_after = sfn.describe_state_machine(stateMachineArn=v1_arn)
    assert json.loads(v1_after["definition"]) == _DEF_V1 and v1_after.get("description") == "v1 snapshot", (
        "version 1's definition or description changed after a rejected UpdateStateMachine call"
    )
    v2_after = sfn.describe_state_machine(stateMachineArn=v2_arn)
    assert json.loads(v2_after["definition"]) == _DEF_V2 and v2_after.get("description") == "v2 snapshot", (
        "version 2's definition or description changed after a rejected UpdateStateMachine call"
    )


def _list_versions(sfn, sm_arn):
    out = []
    next_token = None
    while True:
        kwargs = {"stateMachineArn": sm_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        page = sfn.list_state_machine_versions(**kwargs)
        out.extend(v["stateMachineVersionArn"] for v in page["stateMachineVersions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
