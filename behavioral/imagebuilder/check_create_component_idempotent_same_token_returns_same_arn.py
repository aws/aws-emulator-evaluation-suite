"""create-component-idempotent-same-token-returns-same-arn."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-idempotent-same-token-returns-same-arn"
GROUP = "idempotency"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying CreateComponent with the same clientToken and identical parameters returns the same ARN
    (no duplicate build version is minted), confirmed by an independent ListComponentBuildVersions read;
    deleting the component then makes it genuinely gone."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-component-")
    token = str(uuid.uuid4())
    kwargs = dict(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=token,
        tags={"sim2real": CHECK},
    )

    first_arn = ib.create_component(**kwargs)["componentBuildVersionArn"]
    ctx.on_cleanup(_ignore_not_found(lambda: ib.delete_component(componentBuildVersionArn=first_arn)))

    second_arn = ib.create_component(**kwargs)["componentBuildVersionArn"]
    # a genuinely new build version would carry an incremented build-number suffix;
    # an idempotent replay returns the identical ARN instead.
    assert second_arn == first_arn, f"expected replay to return {first_arn!r}, got {second_arn!r}"

    # independent read through a different operation than the mutating CreateComponent
    # calls: exactly one build version exists for this semantic version, so the replay
    # did not mint a second one that the ARN comparison alone could miss.
    version_arn = first_arn.rsplit("/", 1)[0]
    versions = ib.list_component_build_versions(componentVersionArn=version_arn)["componentSummaryList"]
    assert len(versions) == 1, f"expected exactly one build version, found {[v['arn'] for v in versions]!r}"
    assert versions[0]["arn"] == first_arn, (
        f"expected the sole build version to be {first_arn!r}, got {versions[0]['arn']!r}"
    )

    # the teardown this check already performs is a free negative assertion: prove it
    # here, then let on_cleanup's repeat delete no-op harmlessly.
    ib.delete_component(componentBuildVersionArn=first_arn)
    code, msg = _error(lambda: ib.get_component(componentBuildVersionArn=first_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected = f"The following required resource 'Component' cannot be found: '{first_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    mutate_code, mutate_msg = _error(lambda: ib.delete_component(componentBuildVersionArn=first_arn))
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
