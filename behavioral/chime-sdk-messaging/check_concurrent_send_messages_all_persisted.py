"""concurrent-send-messages-all-persisted."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-send-messages-all-persisted"
GROUP = "concurrency"
SERVICES = ["chime-sdk-messaging"]

# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it.
_REGION = "us-east-1"
_FANOUT = 8
_HISTORY_DEADLINE_S = 60.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _app_instance(ctx, identity):
    arn = identity.create_app_instance(
        Name=ctx.unique_name("sim2real-behav-ai-"),
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: identity.delete_app_instance(AppInstanceArn=arn))
    return arn


def _user(ctx, identity, app_instance, label):
    return identity.create_app_instance_user(
        AppInstanceArn=app_instance,
        AppInstanceUserId=ctx.unique_name(f"sim2real-behav-{label}-"),
        Name=label,
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight concurrent sends into one channel mint eight distinct MessageIds, and the paginated
    ASCENDING history holds exactly those ids and bodies once each, in non-decreasing
    CreatedTimestamp order, with the sender attributed."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    sender = _user(ctx, identity, app_instance, "sender")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=sender,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=sender))

    def _send(index: int) -> str:
        return messaging.send_channel_message(
            ChannelArn=channel,
            Content=f"sim2real-concurrent-{index:02d}",
            Type="STANDARD",
            Persistence="PERSISTENT",
            ChimeBearer=sender,
            ClientRequestToken=uuid.uuid4().hex,
        )["MessageId"]

    with ThreadPoolExecutor(max_workers=_FANOUT) as pool:
        minted = list(pool.map(_send, range(_FANOUT)))

    assert len(set(minted)) == _FANOUT, (
        f"{_FANOUT} concurrent sends minted only {len(set(minted))} distinct MessageIds: {minted!r}"
    )

    def _walk() -> list:
        # Paginate deliberately small: the history must be complete across page boundaries.
        history, token = [], None
        while True:
            page = messaging.list_channel_messages(
                ChannelArn=channel, ChimeBearer=sender, MaxResults=3, SortOrder="ASCENDING",
                **({"NextToken": token} if token else {}),
            )
            history.extend(page["ChannelMessages"])
            token = page.get("NextToken")
            if not token:
                return history

    # The history is read until it lists every minted id, so a read that lands before the
    # sends are visible is not graded as a lost message.
    deadline = time.monotonic() + _budget_s(ctx, _HISTORY_DEADLINE_S)
    history = _walk()
    while not set(minted) <= {m["MessageId"] for m in history}:
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the channel history wait: the run budget ended first; not graded")
            break
        time.sleep(1.0)
        history = _walk()

    stored = [m["MessageId"] for m in history]
    assert len(stored) == len(set(stored)), f"the history lists a message twice: {stored!r}"
    assert set(stored) == set(minted), (
        f"the history holds {sorted(set(stored))!r}, expected exactly the {_FANOUT} concurrently "
        f"sent ids {sorted(set(minted))!r}"
    )

    stamps = [m["CreatedTimestamp"] for m in history]
    assert stamps == sorted(stamps), (
        f"SortOrder=ASCENDING returned timestamps out of order: {stamps!r}"
    )
    contents = {m["Content"] for m in history}
    assert contents == {f"sim2real-concurrent-{i:02d}" for i in range(_FANOUT)}, (
        f"the stored contents are {sorted(contents)!r}, expected one body per concurrent send"
    )

    probe = messaging.get_channel_message(
        ChannelArn=channel, MessageId=minted[-1], ChimeBearer=sender
    )["ChannelMessage"]
    assert probe["Sender"]["Arn"] == sender, (
        f"a concurrently sent message attributes its sender as {probe['Sender']['Arn']!r}, "
        f"expected {sender!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
