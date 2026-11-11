"""send-message-idempotent-client-request-token."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "send-message-idempotent-client-request-token"
GROUP = "data-plane"
SERVICES = ["chime-sdk-messaging"]

# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it.
_REGION = "us-east-1"


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


def _paginated(op, key, **kwargs):
    out, token = [], None
    while True:
        page = op(MaxResults=2, **({"NextToken": token} if token else {}), **kwargs)
        out.extend(page[key])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Replaying SendChannelMessage with the same ClientRequestToken and content returns the first
    MessageId and status and stores exactly one message; a fresh token stores a second one."""
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

    token = uuid.uuid4().hex
    body = dict(
        ChannelArn=channel, Content="sim2real-replayed-body", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=sender,
    )
    first = messaging.send_channel_message(ClientRequestToken=token, **body)
    replay = messaging.send_channel_message(ClientRequestToken=token, **body)
    assert replay["MessageId"] == first["MessageId"], (
        f"the replay minted a new MessageId {replay['MessageId']!r}; the first send returned "
        f"{first['MessageId']!r}"
    )
    assert replay["Status"]["Value"] == first["Status"]["Value"], (
        f"the replay reported status {replay['Status']!r}, the first send {first['Status']!r}"
    )

    after_replay = _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=sender
    )
    assert [m["MessageId"] for m in after_replay] == [first["MessageId"]], (
        f"the replay stored a second message: the channel holds "
        f"{[m['MessageId'] for m in after_replay]!r}"
    )

    fresh = messaging.send_channel_message(ClientRequestToken=uuid.uuid4().hex, **body)
    assert fresh["MessageId"] != first["MessageId"], (
        f"a send with a FRESH token reused the MessageId {fresh['MessageId']!r} — the token, not "
        f"the content, is the idempotency key"
    )
    after_fresh = {m["MessageId"] for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=sender
    )}
    assert after_fresh == {first["MessageId"], fresh["MessageId"]}, (
        f"the channel holds {sorted(after_fresh)!r}, expected exactly the deduplicated first "
        f"message and the freshly tokenised one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
