"""batch-get-channel-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-channel-partial-failure"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetChannel with a mix of a real ARN and a well-formed but non-existent ARN
    returns the real channel in `channels` and reports the missing one in `errors`,
    rather than failing the whole batch."""
    ivs = ctx.client("ivs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-ivs-batchget-")
    real_arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=real_arn))

    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account_id}:channel/sim2real0missing00"

    resp = ivs.batch_get_channel(arns=[real_arn, bogus_arn])

    channels = resp["channels"]
    assert len(channels) == 1, f"expected 1 resolved channel, got {len(channels)}: {channels}"
    assert channels[0]["arn"] == real_arn, f"expected resolved arn {real_arn}, got {channels[0]['arn']}"

    errors = resp["errors"]
    assert len(errors) == 1, f"expected 1 per-item error, got {len(errors)}: {errors}"
    assert errors[0]["arn"] == bogus_arn, f"expected error arn {bogus_arn}, got {errors[0]['arn']}"
    assert errors[0]["code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for missing channel, got {errors[0]['code']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
