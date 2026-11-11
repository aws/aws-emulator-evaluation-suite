"""create-component-idempotent-mismatch-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-idempotent-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying CreateComponent with the same clientToken but a different description is rejected, and no second version is minted."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-component-")
    token = str(uuid.uuid4())
    tag_set = {"sim2real-check": CHECK}

    first_arn = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        description="original description",
        clientToken=token,
        tags=tag_set,
    )["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=first_arn))

    code, msg = _error(
        lambda: ib.create_component(
            name=name,
            semanticVersion="1.0.0",
            platform="Linux",
            data=_COMPONENT_DATA,
            description="a totally different description",
            clientToken=token,
            tags=tag_set,
        )
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException for a same-token/different-description "
        f"replay, got {code!r}"
    )
    expected = "The request parameters do not match those in the original idempotent request."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: the stored component still has the original description, not the mismatched one
    got = ib.get_component(componentBuildVersionArn=first_arn)["component"]
    assert got["description"] == "original description", (
        f"expected the mismatched replay to leave the stored description untouched, "
        f"got {got['description']!r}"
    )

    # restore: the identical original call (same token, same params) is a correctly-idempotent
    # no-op that returns the same ARN, not a casualty of some blanket "reject any token reuse" rule
    restored_arn = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        description="original description",
        clientToken=token,
        tags=tag_set,
    )["componentBuildVersionArn"]
    assert restored_arn == first_arn, (
        f"expected an identical replay (same clientToken, same params) to return the same ARN "
        f"{first_arn!r}, got {restored_arn!r}"
    )

    # positive control: a fresh clientToken + fresh name creates successfully
    control_name = ctx.unique_name("sim2real-component-control-")
    control_arn = ib.create_component(
        name=control_name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags=tag_set,
    )["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=control_arn))
    got_control = ib.get_component(componentBuildVersionArn=control_arn)["component"]
    assert got_control["name"] == control_name, (
        f"expected the control component's name to be {control_name!r}, got {got_control['name']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
