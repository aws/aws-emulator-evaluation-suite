"""non-persistent-message-read-back-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "non-persistent-message-read-back-rejected"
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


def _error(fn, **kwargs):
    """The AWS error code and message raised by *fn*. An unexpected SUCCESS raises: a target that
    accepts what real AWS refuses is the strongest signal here, never a falsy code."""
    try:
        fn(**kwargs)
    except Exception as exc:  # botocore raises a per-error subclass of ClientError
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"{getattr(fn, '__name__', fn)!r} succeeded; real AWS rejects it")


def _paginated(op, key, **kwargs):
    out, token = [], None
    while True:
        page = op(MaxResults=2, **({"NextToken": token} if token else {}), **kwargs)
        out.extend(page[key])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A NON_PERSISTENT message is acknowledged SENT with a MessageId, GetChannelMessage on that id
    fails with ForbiddenException "You do not have sufficient access to perform this action.", and
    the history lists only a persistent message sent afterwards, which reads back."""
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

    ephemeral = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-ephemeral-body", Type="STANDARD",
        Persistence="NON_PERSISTENT", ChimeBearer=sender, ClientRequestToken=uuid.uuid4().hex,
    )
    assert ephemeral["Status"]["Value"] == "SENT", (
        f"the ephemeral send reported status {ephemeral['Status']!r}, expected SENT"
    )
    ephemeral_id = ephemeral["MessageId"]

    refused, message = _error(
        messaging.get_channel_message, ChannelArn=channel, MessageId=ephemeral_id,
        ChimeBearer=sender,
    )
    assert refused == "ForbiddenException", (
        f"GetChannelMessage on a NON_PERSISTENT message's id got {refused!r}, expected "
        f"'ForbiddenException'"
    )
    expected = "You do not have sufficient access to perform this action."
    assert message == expected, (
        f"GetChannelMessage refused with message {message!r}, expected {expected!r}"
    )

    # Positive control: a persistent message through the same channel and bearer is retrievable.
    durable_id = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-durable-body", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=sender, ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]
    durable = messaging.get_channel_message(
        ChannelArn=channel, MessageId=durable_id, ChimeBearer=sender
    )["ChannelMessage"]
    assert durable["Content"] == "sim2real-durable-body", (
        f"the persistent control message read back as {durable.get('Content')!r}"
    )

    history = [m["MessageId"] for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=sender
    )]
    assert history == [durable_id], (
        f"the channel's history is {history!r}, expected only the persistent message "
        f"{durable_id!r} — the ephemeral id {ephemeral_id!r} must not be stored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
