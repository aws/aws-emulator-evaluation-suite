"""create-channel-invalid-name-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel rejects a name containing characters outside ^[a-zA-Z0-9-_]*$
    with ValidationException and creates nothing; the same call with a valid name
    succeeds (positive control)."""
    ivs = ctx.client("ivs")
    bad_name = ctx.unique_name("sim2real-ivs-badname-") + " not/valid!"

    error, bad_arn = _create_channel_error(ivs, bad_name)
    if bad_arn:
        ctx.on_cleanup(lambda: ivs.delete_channel(arn=bad_arn))
        raise AssertionError(f"CreateChannel accepted the invalid name {bad_name!r}: {bad_arn}")
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "CreateChannel.name does not match the required pattern ^[a-zA-Z0-9-_]*$"
    ), f"unexpected CreateChannel validation message: {error['Message']!r}"

    found = [c for c in _all_channels(ivs) if c["name"] == bad_name]
    assert found == [], f"invalid-named channel was created: {found}"

    good_name = ctx.unique_name("sim2real-ivs-goodname-")
    arn = ivs.create_channel(name=good_name, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))
    got = ivs.get_channel(arn=arn)["channel"]
    assert got["name"] == good_name, f"expected name {good_name!r}, got {got['name']!r}"


def _create_channel_error(ivs, name):
    """Returns (error, arn): arn is set (and error is None) on unexpected success, so the
    caller registers cleanup for an over-permissive target's channel and then raises."""
    try:
        resp = ivs.create_channel(name=name)
    except ClientError as e:
        return e.response["Error"], None
    return None, resp["channel"]["arn"]


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
