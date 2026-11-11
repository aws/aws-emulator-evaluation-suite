"""batch-get-stream-key-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-stream-key-partial-failure"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetStreamKey reports a per-item error for a missing ARN instead of failing the whole call."""
    ivs = ctx.client("ivs")
    created = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-bgsk-"), tags={"purpose": "sim2real"}
    )
    channel_arn = created["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))
    valid_arn = created["streamKey"]["arn"]

    missing_arn = valid_arn[: valid_arn.rindex("/") + 1] + "nonexistentkey0"

    response = ivs.batch_get_stream_key(arns=[valid_arn, missing_arn])

    returned_arns = {k["arn"] for k in response["streamKeys"]}
    assert returned_arns == {valid_arn}, (
        f"expected only the resolvable key {valid_arn!r} in streamKeys, got {returned_arns!r}"
    )
    # Stream-key values are sensitive; BatchGet must still surface them for resolved keys.
    assert response["streamKeys"][0]["value"], "resolved stream key must carry its secret value"

    errors = response["errors"]
    assert len(errors) == 1, f"expected exactly one per-item error, got {len(errors)}: {errors!r}"
    assert errors[0]["arn"] == missing_arn, (
        f"expected the error to name the missing arn {missing_arn!r}, got {errors[0]['arn']!r}"
    )
    assert errors[0]["code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the missing key, got {errors[0]['code']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
