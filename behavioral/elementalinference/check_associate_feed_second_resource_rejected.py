"""associate-feed-second-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-feed-second-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["elementalinference"]


def _smart_crop_output(name: str) -> dict:
    return {"name": name, "outputConfig": {"cropping": {}}, "status": "ENABLED"}


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A feed can have only one associated resource: a second AssociateFeed call is rejected with ValidationException."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_smart_crop_output("out-a")], tags={"sim2real": "behavioral"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_a = ctx.unique_name("sim2real-ei-src-a-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_a, outputs=[])

    resource_b = ctx.unique_name("sim2real-ei-src-b-")
    code, message = _error_code(
        lambda: ei.associate_feed(
            id=feed_id, associatedResourceName=resource_b, outputs=[_smart_crop_output("out-b")]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "The feed is already associated with a resource.", message

    # Effect absent: the original association and output set are unchanged.
    got = ei.get_feed(id=feed_id)
    assert got["association"]["associatedResourceName"] == resource_a, (
        f"expected association unchanged at {resource_a!r}, got {got['association']!r}"
    )
    assert {o["name"] for o in got["outputs"]} == {"out-a"}, f"unexpected outputs: {got['outputs']}"

    # Positive control: associating a fresh feed's first resource succeeds.
    control_name = ctx.unique_name("sim2real-ei-feed-ctl-")
    control_id = ei.create_feed(
        name=control_name, outputs=[_smart_crop_output("out-a")], tags={"sim2real": "behavioral"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=control_id))
    ei.associate_feed(id=control_id, associatedResourceName=resource_b, outputs=[])
    control_got = ei.get_feed(id=control_id)
    assert control_got["association"]["associatedResourceName"] == resource_b, (
        f"expected fresh feed to associate {resource_b!r}, got {control_got['association']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
