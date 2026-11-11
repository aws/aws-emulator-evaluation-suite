"""create-secret-name-exceeds-max-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-secret-name-exceeds-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecret with a Name longer than the documented 512-character maximum
    (see API_CreateSecret Request Parameters: Name Length Constraints) is rejected
    rather than truncated or silently accepted, and no secret is ever created for it."""
    sm = ctx.client("secretsmanager")

    prefix = ctx.unique_name("sim2real-behav-sm-")
    oversized_name = prefix + ("x" * 600)
    assert len(oversized_name) > 512, f"test name only {len(oversized_name)} chars, need > 512"

    code, message = _refusal(
        lambda: sm.create_secret(Name=oversized_name, SecretString="value")
    )
    assert code == "ValidationException", f"unexpected code {code!r}"
    # AWS answers an oversized name with its generic invalid-name message, not a length message.
    assert message == (
        "Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!"
    ), f"unexpected refusal message: {message!r}"

    # Effect absent: no secret exists whose name matches the rejected oversized
    # identifier (querying by that identifier itself also fails length/pattern
    # validation, so we search ListSecrets by the unique prefix instead).
    found = [
        s
        for page in sm.get_paginator("list_secrets").paginate(
            Filters=[{"Key": "name", "Values": [prefix]}]
        )
        for s in page.get("SecretList", [])
    ]
    assert found == [], f"expected no secret matching prefix {prefix!r}, found {found!r}"

    # Positive control: a name within the limit is accepted normally.
    valid_name = ctx.unique_name("sim2real-behav-sm-ok-")
    created = sm.create_secret(
        Name=valid_name,
        SecretString="value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=created["ARN"], ForceDeleteWithoutRecovery=True)
    )
    assert created["Name"] == valid_name, f"expected {valid_name!r}, got {created['Name']!r}"
    described = sm.describe_secret(SecretId=created["ARN"])
    assert described["Name"] == valid_name, (
        f"expected {valid_name!r}, got {described['Name']!r}"
    )


def _refusal(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, so a target
    that accepts the oversized name fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
