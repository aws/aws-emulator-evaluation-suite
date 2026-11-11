"""delete-channel-message-by-moderator-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-channel-message-by-moderator-rejected"
GROUP = "moderation"
SERVICES = ["chime-sdk-messaging"]

# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it.
_REGION = "us-east-1"
_FORBIDDEN = "You do not have sufficient access to perform this action."


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
    """The AWS error (code, message) raised by *fn*. An unexpected SUCCESS raises: a target
    that accepts what real AWS refuses is the strongest signal here, never a falsy code."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A channel moderator deleting its own message gets ForbiddenException with the exact message
    and the message keeps its content; once the same bearer is an AppInstanceAdmin, the same delete
    succeeds within 20 s and the channel lists no messages."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=owner))

    moderators = [m["Moderator"]["Arn"] for m in _paginated(
        messaging.list_channel_moderators, "ChannelModerators",
        ChannelArn=channel, ChimeBearer=owner,
    )]
    assert moderators == [owner], (
        f"the creator should be the channel's sole moderator; ListChannelModerators returned "
        f"{moderators!r}"
    )

    message_id = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-moderator-owned", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=owner, ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]

    refused, refused_message = _error(
        messaging.delete_channel_message, ChannelArn=channel, MessageId=message_id,
        ChimeBearer=owner,
    )
    assert refused == "ForbiddenException", (
        f"a moderator deleting their own message got {refused!r}, expected 'ForbiddenException'"
    )
    assert refused_message == _FORBIDDEN, (
        f"a moderator deleting their own message returned the message {refused_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )
    survived = messaging.get_channel_message(
        ChannelArn=channel, MessageId=message_id, ChimeBearer=owner
    )["ChannelMessage"]
    assert survived["Content"] == "sim2real-moderator-owned", (
        f"the refused delete changed the message: content is {survived.get('Content')!r}"
    )

    # Positive control: the same bearer, the same call, now an AppInstanceAdmin.
    identity.create_app_instance_admin(AppInstanceAdminArn=owner, AppInstanceArn=app_instance)
    deleted = None
    for _ in range(10):
        try:
            messaging.delete_channel_message(
                ChannelArn=channel, MessageId=message_id, ChimeBearer=owner
            )
            deleted = True
            break
        except Exception as exc:  # the admin promotion is not read-your-writes for messaging
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "ForbiddenException":
                raise
            time.sleep(2)
    assert deleted, (
        "DeleteChannelMessage stayed ForbiddenException for 20s after the bearer became an "
        f"AppInstanceAdmin of {app_instance!r}"
    )

    remaining = [m["MessageId"] for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=owner,
    )]
    assert remaining == [], (
        f"after the admin delete the channel still lists {remaining!r}, expected no messages"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
