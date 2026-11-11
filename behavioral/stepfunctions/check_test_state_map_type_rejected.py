"""test-state-map-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-map-type-rejected"
GROUP = "state_machine_lifecycle"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity",):
            raise


def _create_sfn_role(ctx) -> str:
    """An execution role for TestState; it is never assumed since TestState creates no execution."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


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


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState refuses a definition whose Type is Map — an inline ItemProcessor with a single
    Pass state included — with InvalidDefinition and the API's own exact message; the identical
    ItemProcessor's lone Pass state, tested directly, succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # Positive control: TestState against the Map's own inner state works on its own, so the
    # refusal below is about the Map wrapper, not about role propagation or a malformed body.
    inner_definition = json.dumps({"Type": "Pass", "End": True})
    control = _await_role(
        lambda: sfn.test_state(definition=inner_definition, roleArn=role_arn, input=json.dumps([1, 2, 3]))
    )
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control}"

    map_definition = json.dumps({
        "Type": "Map",
        "ItemProcessor": {
            "ProcessorConfig": {"Mode": "INLINE"},
            "StartAt": "P",
            "States": {"P": {"Type": "Pass", "End": True}},
        },
        "End": True,
    })
    err = _error(
        lambda: sfn.test_state(definition=map_definition, roleArn=role_arn, input=json.dumps([1, 2, 3]))
    )
    expected = {
        "Code": "InvalidDefinition",
        "Status": 400,
        "Message": (
            "TestState API does not support Map or Parallel states. Supported state types "
            "include: [Task, Wait, Pass, Succeed, Fail, Choice]"
        ),
    }
    assert err == expected, f"TestState on a Map-type definition: expected {expected}, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
