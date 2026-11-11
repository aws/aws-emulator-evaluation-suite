"""multitrack-container-format-incompatible-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multitrack-container-format-incompatible-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When multitrackInputConfiguration.enabled is true, containerFormat must be
    FRAGMENTED_MP4; requesting TS is rejected with ValidationException and no channel
    is created, while the same request with FRAGMENTED_MP4 (positive control) succeeds."""
    ivs = ctx.client("ivs")
    bad_name = ctx.unique_name("sim2real-ivs-mtbad-")

    error = _error(
        lambda: ivs.create_channel(
            name=bad_name,
            type="STANDARD",
            multitrackInputConfiguration={
                "enabled": True,
                "policy": "ALLOW",
                "maximumResolution": "HD",
            },
            containerFormat="TS",
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for multitrack+TS, got {error['Code']}"
    )
    assert error["Message"] == (
        "Request member: multitrack_input_configuration.enabled failed to satisfy the "
        "constraints: invalid value for multitrack input configuration enabled and container format"
    ), repr(error["Message"])

    found = [c for c in _all_channels(ivs) if c["name"] == bad_name]
    assert found == [], f"an incompatible channel was created: {found}"

    good_name = ctx.unique_name("sim2real-ivs-mtgood-")
    arn = ivs.create_channel(
        name=good_name,
        type="STANDARD",
        multitrackInputConfiguration={
            "enabled": True,
            "policy": "ALLOW",
            "maximumResolution": "HD",
        },
        containerFormat="FRAGMENTED_MP4",
        tags={"purpose": "sim2real"},
    )["channel"]["arn"]

    def _cleanup_channel():
        try:
            ivs.delete_channel(arn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_channel)
    got = ivs.get_channel(arn=arn)["channel"]
    assert got["containerFormat"] == "FRAGMENTED_MP4", (
        f"expected containerFormat FRAGMENTED_MP4 to persist, got {got['containerFormat']}"
    )
    assert got["multitrackInputConfiguration"]["enabled"] is True, (
        f"expected multitrack to stay enabled, got {got['multitrackInputConfiguration']}"
    )

    ivs.delete_channel(arn=arn)
    not_found = _error(lambda: ivs.get_channel(arn=arn))
    assert not_found["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted channel, got {not_found['Code']}"
    )
    assert not_found["Message"] == f"Resource: {arn} not found", repr(not_found["Message"])
    mutate = _error(lambda: ivs.update_channel(arn=arn, latencyMode="NORMAL"))
    assert mutate["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted channel, got {mutate['Code']}"
    )
    assert mutate["Message"] == f"Resource: {arn} not found", repr(mutate["Message"])


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _all_channels(ivs):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ivs.list_channels(**kwargs)
        out.extend(resp["channels"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
