"""get-channel-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-channel-not-found"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetChannel on a well-formed ARN for a channel that does not exist raises
    ResourceNotFoundException, while the identical call against a real channel
    succeeds."""
    ivs = ctx.client("ivs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:channel/does-not-exist-0000000"

    error = _error(lambda: ivs.get_channel(arn=bogus_arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent channel, got {error['Code']!r}"
    )
    assert error["Message"] == f"Resource: {bogus_arn} not found", repr(error["Message"])

    # Positive control: the identical call against a real channel succeeds -- without
    # this, "rejects a nonexistent channel" is indistinguishable from "rejects every
    # GetChannel call".
    name = ctx.unique_name("sim2real-ivs-getchannel-")
    created = ivs.create_channel(name=name, tags={"probe": "sim2real"})["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=created["arn"]))

    real = ivs.get_channel(arn=created["arn"])["channel"]
    assert real["arn"] == created["arn"], (
        f"expected get_channel to return the created channel's arn {created['arn']!r}, got {real['arn']!r}"
    )
    assert real["name"] == name, f"expected channel name {name!r}, got {real['name']!r}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
