"""thing-versioning-and-recreate-identity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "thing-versioning-and-recreate-identity"
GROUP = 'thing-lifecycle'
SERVICES = ['iot']


def expect_error(fn, code, message):
    """Call fn(); assert the ClientError it raises carries exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code}, got {err.get('Code')}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code}, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeat CreateThing is idempotent; UpdateThing bumps the version and a stale
    expectedVersion is rejected with state untouched; after DeleteThing every read and
    write 404s, and CreateThing with the same name mints a new thingId at version 1."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-thing-fresh-")

    created = iot.create_thing(thingName=name, attributePayload={"attributes": {"env": "v1"}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=name))
    first_id = created["thingId"]
    first_arn = created["thingArn"]
    assert first_arn == f"arn:aws:iot:{ctx.region}:{ctx.account}:thing/{name}", first_arn

    repeat = iot.create_thing(thingName=name, attributePayload={"attributes": {"env": "v1"}})
    assert repeat["thingId"] == first_id, (
        f"an identical repeat CreateThing must return the same thingId, got {repeat['thingId']!r} "
        f"vs {first_id!r}"
    )
    assert repeat["thingArn"] == first_arn, repeat["thingArn"]

    iot.update_thing(
        thingName=name, expectedVersion=1, attributePayload={"attributes": {"env": "v2"}}
    )
    bumped = iot.describe_thing(thingName=name)
    assert bumped["version"] == 2, f"expected version 2 after the guarded update, got {bumped['version']}"
    assert bumped["attributes"] == {"env": "v2"}, bumped["attributes"]
    assert bumped["thingId"] == first_id, "an attribute update must not change the thingId"

    _stale = (
        "VersionConflictException",
        f"The version for thing {name} does not match the expected version.",
    )
    expect_error(
        lambda: iot.update_thing(
            thingName=name, expectedVersion=1, attributePayload={"attributes": {"env": "stale"}}
        ),
        *_stale,
    )
    untouched = iot.describe_thing(thingName=name)
    assert untouched["version"] == 2, (
        f"a rejected stale update must leave the version at 2, got {untouched['version']}"
    )
    assert untouched["attributes"] == {"env": "v2"}, (
        f"a rejected stale update must leave attributes at env=v2, got {untouched['attributes']}"
    )

    iot.delete_thing(thingName=name)

    _describe_gone = ("ResourceNotFoundException", f"Thing {ctx.account}:{name} not found.")
    expect_error(lambda: iot.describe_thing(thingName=name), *_describe_gone)

    _update_gone = ("ResourceNotFoundException", f"Thing {name} not found.")
    expect_error(
        lambda: iot.update_thing(thingName=name, attributePayload={"attributes": {"env": "x"}}),
        *_update_gone,
    )

    recreated = iot.create_thing(thingName=name)
    assert recreated["thingArn"] == first_arn, recreated["thingArn"]
    assert recreated["thingId"] != first_id, (
        f"a thing recreated after delete must mint a new thingId, got the same {first_id!r}"
    )

    fresh = iot.describe_thing(thingName=name)
    assert fresh["thingId"] == recreated["thingId"], fresh["thingId"]
    assert fresh["version"] == 1, f"a recreated thing must start at version 1, got {fresh['version']}"
    assert fresh.get("attributes", {}) == {}, (
        f"a recreated thing must carry no attributes from its deleted predecessor, got {fresh.get('attributes')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
