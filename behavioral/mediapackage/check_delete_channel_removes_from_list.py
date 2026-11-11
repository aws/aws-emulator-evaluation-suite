"""delete-channel-removes-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-channel-removes-from-list"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted Channel disappears from ListChannels (DeleteChannel is 202 Accepted /
    may be asynchronous, so this polls rather than asserting immediately), and an
    independent DescribeChannel read on the same id then returns NotFoundException."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": "true"})
    deleted = {"v": False}

    def _cleanup():
        if not deleted["v"]:
            mp.delete_channel(Id=channel_id)

    ctx.on_cleanup(_cleanup)

    assert channel_id in _list_all_channel_ids(mp)

    mp.delete_channel(Id=channel_id)
    deleted["v"] = True

    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if channel_id not in _list_all_channel_ids(mp):
            break
        time.sleep(3.0)
    else:
        raise AssertionError(f"channel {channel_id} still appears in ListChannels after delete")

    code, message = _error_code(lambda: mp.describe_channel(Id=channel_id))
    assert code == "NotFoundException", (
        f"expected deleted channel {channel_id} to 404 on DescribeChannel, got {code!r}"
    )
    expected_message = f"channel with id={channel_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all_channel_ids(mp) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = mp.list_channels(**kwargs)
        ids.extend(c["Id"] for c in resp.get("Channels", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
