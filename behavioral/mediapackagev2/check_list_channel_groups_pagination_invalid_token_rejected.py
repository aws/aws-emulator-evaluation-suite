"""list-channel-groups-pagination-invalid-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channel-groups-pagination-invalid-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


INVALID_TOKEN = (
    "Validation error encountered at request.nextToken: You've provided an invalid pagination "
    "token in your request. Check your token and then try again"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a token real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(
        f"real AWS rejects a malformed NextToken, but ListChannelGroups SUCCEEDED and returned "
        f"{result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListChannelGroups with a malformed NextToken is rejected with ValidationException,
    while calling it without a token (positive control) succeeds and includes a freshly
    created group."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    err = _client_error(lambda: mp.list_channel_groups(NextToken="not-a-real-pagination-token"))
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", (
        f"a malformed NextToken was rejected with {code!r}, expected 'ValidationException'"
    )
    message = err.response["Error"]["Message"]
    assert message == INVALID_TOKEN, f"expected message {INVALID_TOKEN!r}, got {message!r}"

    # Positive control: no token succeeds and the created group is discoverable.
    names = set()
    next_token = None
    for _ in range(50):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = mp.list_channel_groups(**kwargs)
        names.update(item["ChannelGroupName"] for item in page["Items"])
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert group in names, (
        f"positive control: {group!r} was not discoverable via ListChannelGroups; saw {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
