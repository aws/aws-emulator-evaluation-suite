"""create-state-machine-publish-idempotent-same-version-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-publish-idempotent-same-version-arn"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_DEF = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeated CreateStateMachine with identical name, definition, roleArn, publish=true and
    versionDescription is idempotent: it returns the same stateMachineArn and the same
    stateMachineVersionArn rather than publishing a second version.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-pubidem-")
    kwargs = dict(
        name=name,
        definition=json.dumps(_DEF),
        roleArn=role_arn,
        publish=True,
        versionDescription="first published version",
        tags=[{"key": "sim2real", "value": "1"}],
    )

    first = _create_sm_retrying(sfn, **kwargs)
    arn = first["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    version_arn = first["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))
    assert version_arn, "expected a stateMachineVersionArn on the first publish=true create"

    second = sfn.create_state_machine(**kwargs)
    assert second["stateMachineArn"] == arn, (
        "idempotent CreateStateMachine must return the same stateMachineArn, got "
        f"{second['stateMachineArn']!r} vs {arn!r}"
    )
    assert second["stateMachineVersionArn"] == version_arn, (
        "an identical publish=true repeat must return the same stateMachineVersionArn, got "
        f"{second['stateMachineVersionArn']!r} vs {version_arn!r}"
    )

    versions = _list_versions(sfn, arn)
    assert versions == [version_arn], (
        f"the idempotent repeat must not publish a second version, got {versions!r}"
    )

    described = sfn.describe_state_machine(stateMachineArn=arn)
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"


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
