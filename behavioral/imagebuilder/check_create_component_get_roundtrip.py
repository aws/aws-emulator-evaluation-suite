"""create-component-get-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-get-roundtrip"
GROUP = "control-plane"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component for behavioral fidelity checks
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponent persists a real component whose GetComponent reflects the submitted document/platform/version; DeleteComponent then makes it genuinely gone."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-component-")
    resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(_ignore_not_found(lambda: ib.delete_component(componentBuildVersionArn=arn)))

    got = ib.get_component(componentBuildVersionArn=arn)["component"]
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got.get('arn')!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got.get('name')!r}"
    assert got["version"] == "1.0.0", f"expected version '1.0.0', got {got.get('version')!r}"
    assert got["platform"] == "Linux", f"expected platform 'Linux', got {got.get('platform')!r}"
    assert got["type"] == "BUILD", f"a user-created component must be type BUILD, got {got.get('type')!r}"
    assert got["data"] == _COMPONENT_DATA, f"expected data to round-trip verbatim, got {got.get('data')!r}"

    # The delete this check already performs at teardown is a free negative assertion —
    # prove it here instead, then let on_cleanup's repeat delete no-op harmlessly.
    ib.delete_component(componentBuildVersionArn=arn)
    code, msg = _error(lambda: ib.get_component(componentBuildVersionArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected = f"The following required resource 'Component' cannot be found: '{arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    mutate_code, mutate_msg = _error(lambda: ib.delete_component(componentBuildVersionArn=arn))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted component to also fail not-found, got {mutate_code!r}"
    )
    assert mutate_msg == expected, f"expected message {expected!r}, got {mutate_msg!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    """Teardown wrapper: a resource the check already deleted reads as not-found; anything else raises."""
    def go():
        try:
            fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    return go


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
