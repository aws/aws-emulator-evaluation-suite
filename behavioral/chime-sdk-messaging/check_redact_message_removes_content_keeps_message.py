"""redact-message-removes-content-keeps-message."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "redact-message-removes-content-keeps-message"
GROUP = "moderation"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """RedactChannelMessage on an edited message removes Content and Metadata and sets Redacted,
    keeping MessageId, CreatedTimestamp and status SENT and advancing LastUpdatedTimestamp; a second
    member listing the channel sees the same redacted message."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    reader = _user(ctx, identity, app_instance, "reader")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=owner))
    messaging.create_channel_membership(
        ChannelArn=channel, MemberArn=reader, Type="DEFAULT", ChimeBearer=owner
    )

    message_id = messaging.send_channel_message(
        ChannelArn=channel,
        Content="sim2real-original-secret",
        Metadata="sim2real-original-meta",
        Type="STANDARD",
        Persistence="PERSISTENT",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]

    messaging.update_channel_message(
        ChannelArn=channel, MessageId=message_id, Content="sim2real-edited-secret",
        Metadata="sim2real-edited-meta", ChimeBearer=owner,
    )
    edited = messaging.get_channel_message(
        ChannelArn=channel, MessageId=message_id, ChimeBearer=owner
    )["ChannelMessage"]
    assert edited["Content"] == "sim2real-edited-secret", (
        f"the edit did not take: content is {edited.get('Content')!r}"
    )
    created_at = edited["CreatedTimestamp"]
    edited_at = edited["LastUpdatedTimestamp"]

    redaction = messaging.redact_channel_message(
        ChannelArn=channel, MessageId=message_id, ChimeBearer=owner
    )
    assert redaction["MessageId"] == message_id, (
        f"RedactChannelMessage reported id {redaction['MessageId']!r}, expected {message_id!r}"
    )

    after = messaging.get_channel_message(
        ChannelArn=channel, MessageId=message_id, ChimeBearer=owner
    )["ChannelMessage"]
    assert "Content" not in after, (
        f"redaction left the content readable as {after.get('Content')!r}"
    )
    assert "Metadata" not in after, (
        f"redaction left the metadata readable as {after.get('Metadata')!r}"
    )
    assert after["Redacted"] is True, f"the redacted message reports Redacted={after['Redacted']!r}"
    assert after["CreatedTimestamp"] == created_at, (
        f"redaction moved CreatedTimestamp from {created_at!r} to {after['CreatedTimestamp']!r}"
    )
    assert after["LastUpdatedTimestamp"] > edited_at, (
        f"redaction left LastUpdatedTimestamp at {after['LastUpdatedTimestamp']!r}, "
        f"not advanced past the edit at {edited_at!r}"
    )
    assert after["Status"]["Value"] == "SENT", (
        f"the redacted message's status is {after['Status']!r}, expected it to stay SENT"
    )

    as_reader = _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=reader
    )
    assert [m["MessageId"] for m in as_reader] == [message_id], (
        f"the second member saw {[m['MessageId'] for m in as_reader]!r}, expected the one "
        f"redacted message {message_id!r}"
    )
    assert "Content" not in as_reader[0], (
        f"the second member can still read the redacted content {as_reader[0].get('Content')!r}"
    )
    assert as_reader[0]["Redacted"] is True, (
        f"the second member sees Redacted={as_reader[0]['Redacted']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
