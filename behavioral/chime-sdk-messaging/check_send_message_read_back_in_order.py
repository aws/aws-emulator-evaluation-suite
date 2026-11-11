"""send-message-read-back-in-order."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "send-message-read-back-in-order"
GROUP = "data-plane"
SERVICES = ["chime-sdk-messaging"]

# ===== helpers =====
# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it, so the region is a property of the service rather than
# of the run.
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


def _all_messages(messaging, channel, bearer, **kwargs):
    """Every message in *channel*, following NextToken — a single page is never a bound."""
    out, token = [], None
    while True:
        page = messaging.list_channel_messages(
            ChannelArn=channel, ChimeBearer=bearer, MaxResults=2,
            **({"NextToken": token} if token else {}), **kwargs,
        )
        out.extend(page["ChannelMessages"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Three messages sent in sequence read back intact and in send order (newest-first by default,
    oldest-first with SortOrder=ASCENDING), identically to the sender and to a second member.
    """
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    sender = _user(ctx, identity, app_instance, "sender")
    reader = _user(ctx, identity, app_instance, "reader")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=sender,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=sender))

    messaging.create_channel_membership(
        ChannelArn=channel, MemberArn=reader, Type="DEFAULT", ChimeBearer=sender
    )

    sent = []
    for i in range(3):
        sent.append(messaging.send_channel_message(
            ChannelArn=channel,
            Content=f"sim2real-body-{i}",
            Metadata=f"sim2real-meta-{i}",
            Type="STANDARD",
            Persistence="PERSISTENT",
            ChimeBearer=sender,
            ClientRequestToken=uuid.uuid4().hex,
        )["MessageId"])
    assert len(set(sent)) == 3, f"three sends minted {len(set(sent))} distinct MessageIds: {sent!r}"

    middle = messaging.get_channel_message(
        ChannelArn=channel, MessageId=sent[1], ChimeBearer=sender
    )["ChannelMessage"]
    assert middle["Content"] == "sim2real-body-1", (
        f"GetChannelMessage returned content {middle.get('Content')!r}, expected 'sim2real-body-1'"
    )
    assert middle["Metadata"] == "sim2real-meta-1", (
        f"metadata read back as {middle.get('Metadata')!r}, expected 'sim2real-meta-1'"
    )
    assert middle["Sender"]["Arn"] == sender, (
        f"sender recorded as {middle['Sender']['Arn']!r}, expected {sender!r}"
    )
    assert middle["Persistence"] == "PERSISTENT", (
        f"persistence read back as {middle.get('Persistence')!r}, expected 'PERSISTENT'"
    )
    assert middle["Redacted"] is False, f"a fresh message reported Redacted={middle['Redacted']!r}"
    assert middle["Status"]["Value"] == "SENT", (
        f"status read back as {middle['Status']!r}, expected SENT"
    )

    newest_first = [m["MessageId"] for m in _all_messages(messaging, channel, sender)]
    assert newest_first == list(reversed(sent)), (
        f"default ListChannelMessages order was {newest_first!r}, expected newest-first "
        f"{list(reversed(sent))!r}"
    )

    oldest_first = [
        m["MessageId"] for m in _all_messages(messaging, channel, sender, SortOrder="ASCENDING")
    ]
    assert oldest_first == sent, (
        f"SortOrder=ASCENDING returned {oldest_first!r}, expected send order {sent!r}"
    )

    as_reader = {m["MessageId"]: m.get("Content") for m in _all_messages(messaging, channel, reader)}
    assert set(as_reader) == set(sent), (
        f"the second member saw {sorted(as_reader)!r}, expected the same three {sorted(sent)!r}"
    )
    assert as_reader[sent[2]] == "sim2real-body-2", (
        f"the second member read content {as_reader[sent[2]]!r} for the last message, "
        f"expected 'sim2real-body-2'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
