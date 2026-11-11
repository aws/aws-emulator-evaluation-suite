"""private-channel-non-member-read-denied."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "private-channel-non-member-read-denied"
GROUP = "access-control"
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
    """The AWS error (code, message) raised by *fn*. An unexpected SUCCESS raises: an
    over-permissive target accepting what real AWS refuses is the strongest signal here, never a
    falsy code."""
    try:
        fn(**kwargs)
    except Exception as exc:  # botocore raises a per-error subclass of ClientError
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"{getattr(fn, '__name__', fn)!r} succeeded; real AWS rejects it")


def _all_memberships(messaging, channel, bearer):
    out, token = [], None
    while True:
        page = messaging.list_channel_memberships(
            ChannelArn=channel, ChimeBearer=bearer, MaxResults=2,
            **({"NextToken": token} if token else {}),
        )
        out.extend(page["ChannelMemberships"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A non-member's ListChannelMessages, DescribeChannel and GetChannelMessage on a PRIVATE
    channel fail with ForbiddenException and the exact message and leave it out of the roster,
    while a member lists the same message."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    member = _user(ctx, identity, app_instance, "member")
    outsider = _user(ctx, identity, app_instance, "outsider")

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
        ChannelArn=channel, MemberArn=member, Type="DEFAULT", ChimeBearer=owner
    )
    message_id = messaging.send_channel_message(
        ChannelArn=channel,
        Content="sim2real-members-only",
        Type="STANDARD",
        Persistence="PERSISTENT",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]

    listed, listed_message = _error(
        messaging.list_channel_messages, ChannelArn=channel, ChimeBearer=outsider
    )
    assert listed == "ForbiddenException", (
        f"a non-member listing a PRIVATE channel's messages got {listed!r}, "
        f"expected 'ForbiddenException'"
    )
    assert listed_message == _FORBIDDEN, (
        f"a non-member listing a PRIVATE channel's messages returned the message "
        f"{listed_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )
    described, described_message = _error(
        messaging.describe_channel, ChannelArn=channel, ChimeBearer=outsider
    )
    assert described == "ForbiddenException", (
        f"a non-member describing a PRIVATE channel got {described!r}, "
        f"expected 'ForbiddenException'"
    )
    assert described_message == _FORBIDDEN, (
        f"a non-member describing a PRIVATE channel returned the message {described_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )
    fetched, fetched_message = _error(
        messaging.get_channel_message, ChannelArn=channel, MessageId=message_id,
        ChimeBearer=outsider,
    )
    assert fetched == "ForbiddenException", (
        f"a non-member fetching a message by id got {fetched!r}, expected 'ForbiddenException'"
    )
    assert fetched_message == _FORBIDDEN, (
        f"a non-member fetching a message by id returned the message {fetched_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )

    roster = [m["Member"]["Arn"] for m in _all_memberships(messaging, channel, owner)]
    assert outsider not in roster, (
        f"the refused reads left {outsider!r} in the membership roster {roster!r}"
    )
    assert member in roster, f"the invited member {member!r} is missing from the roster {roster!r}"

    # Positive control: the same read the outsider was refused succeeds for the member.
    as_member = messaging.list_channel_messages(ChannelArn=channel, ChimeBearer=member)
    contents = [m.get("Content") for m in as_member["ChannelMessages"]]
    assert contents == ["sim2real-members-only"], (
        f"the member read {contents!r}, expected exactly ['sim2real-members-only']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
