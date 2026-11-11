"""configuration-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "configuration-duplicate-name-rejected"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with an already-used Name is rejected and does not disturb the
    original configuration's revision history."""
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-msk-cfg-dup-")
    props = b"auto.create.topics.enable=true\n"

    original = kafka.create_configuration(Name=name, ServerProperties=props)
    arn = original["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))
    assert original["LatestRevision"]["Revision"] == 1, (
        f"a fresh configuration must start at revision 1, got {original['LatestRevision']!r}"
    )

    code, message = _error_code(lambda: kafka.create_configuration(Name=name, ServerProperties=props))
    assert code == "ConflictException", f"expected ConflictException for a duplicate Name, got {code!r}"
    assert message == "A resource with this name already exists.", message

    # Effect absent: the original configuration is untouched -- same Arn, still at revision 1.
    described = kafka.describe_configuration(Arn=arn)
    assert described["Arn"] == arn, f"expected the original Arn {arn!r} to be unchanged, got {described['Arn']!r}"
    assert described["LatestRevision"]["Revision"] == 1, (
        f"the rejected duplicate must not advance the original's revision: expected 1, "
        f"got {described['LatestRevision']!r}"
    )

    # Positive control: a genuinely distinct name is accepted without issue, proving the
    # rejection above is specific to the duplicate name rather than CreateConfiguration
    # being broken outright.
    other_name = ctx.unique_name("sim2real-msk-cfg-dup-other-")
    other = kafka.create_configuration(Name=other_name, ServerProperties=props)
    other_arn = other["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=other_arn))
    assert other["Name"] == other_name, f"expected Name {other_name!r} on create, got {other['Name']!r}"
    assert other_arn != arn, f"the distinct-name configuration must get its own Arn, got the original's {arn!r}"

    # Independent read at the destination: the distinct configuration is really there,
    # not just echoed back in the mutating call's own response.
    other_described = kafka.describe_configuration(Arn=other_arn)
    assert other_described["Name"] == other_name, (
        f"expected DescribeConfiguration to read back Name {other_name!r}, got {other_described['Name']!r}"
    )
    assert other_described["LatestRevision"]["Revision"] == 1, (
        f"the distinct configuration must also start at revision 1, got {other_described['LatestRevision']!r}"
    )


def _error_code(fn):
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
