"""configuration-create-describe-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-create-describe-lifecycle"
GROUP = 'configuration'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    Raises if the call succeeds, so an emulator that accepts what AWS refuses fails
    loudly instead of reading as a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration -> ACTIVE with LatestRevision=1; duplicate Name -> ConflictException,
    with the original configuration left untouched."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-config-")
    props = b"auto.create.topics.enable=true\nnum.partitions=1\n"

    resp = msk.create_configuration(
        Name=name,
        Description="behavioral test configuration",
        KafkaVersions=["3.6.0"],
        ServerProperties=props,
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda _a=arn: msk.delete_configuration(Arn=_a))

    assert resp["Name"] == name, f"expected Name={name!r} on create, got {resp.get('Name')!r}"
    assert resp["LatestRevision"]["Revision"] == 1, (
        f"expected initial Revision=1, got {resp['LatestRevision']}"
    )
    assert resp["State"] == "ACTIVE", f"expected State=ACTIVE on create, got {resp['State']!r}"

    described = msk.describe_configuration(Arn=arn)
    assert described["Name"] == name, (
        f"expected Name={name!r} on describe, got {described.get('Name')!r}"
    )
    assert described["State"] == "ACTIVE", (
        f"expected State=ACTIVE on describe, got {described['State']!r}"
    )
    assert described["LatestRevision"]["Revision"] == 1, (
        f"expected Revision=1 on describe, got {described['LatestRevision']}"
    )

    # Duplicate Name must be rejected -- distinct-namespace uniqueness boundary,
    # folded into the lifecycle check rather than a standalone negative check.
    code, message = _err(
        lambda: msk.create_configuration(
            Name=name, ServerProperties=props, KafkaVersions=["3.6.0"]
        )
    )
    assert code == "ConflictException", f"expected ConflictException on dup name, got {code}"
    assert message == "A resource with this name already exists.", message

    # Effect absent: the rejected duplicate must not disturb the original -- an
    # independent read at the destination, not the failed call's own response.
    after = msk.describe_configuration(Arn=arn)
    assert after["Arn"] == arn, f"expected original Arn={arn!r} unchanged, got {after.get('Arn')!r}"
    assert after["State"] == "ACTIVE", (
        f"expected original State=ACTIVE unaffected by rejected dup, got {after['State']!r}"
    )
    assert after["LatestRevision"]["Revision"] == 1, (
        f"expected original Revision to remain 1 after rejected dup, got {after['LatestRevision']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
