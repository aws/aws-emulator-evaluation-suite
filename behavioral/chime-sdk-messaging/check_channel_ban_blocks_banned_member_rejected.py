"""channel-ban-blocks-banned-member-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "channel-ban-blocks-banned-member-rejected"
GROUP = "moderation"
SERVICES = ["chime-sdk-messaging"]

# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it.
_REGION = "us-east-1"
_FORBIDDEN_BANNED = "App instance user is banned from Channel."
_NOT_BANNED = "App instance user is not banned from the specified Channel."


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
    """A ban drops the member from the roster and refuses its send, list and re-add with
    ForbiddenException and the exact ban message while an unbanned member still writes; after
    DeleteChannelBan, DescribeChannelBan fails with NotFoundException and the member rejoins."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    banned = _user(ctx, identity, app_instance, "banned")
    allowed = _user(ctx, identity, app_instance, "allowed")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=owner))

    for member in (banned, allowed):
        messaging.create_channel_membership(
            ChannelArn=channel, MemberArn=member, Type="DEFAULT", ChimeBearer=owner
        )
    before = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-before-ban", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=banned, ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]

    ban = messaging.create_channel_ban(ChannelArn=channel, MemberArn=banned, ChimeBearer=owner)
    ctx.on_cleanup(lambda: messaging.delete_channel_ban(
        ChannelArn=channel, MemberArn=banned, ChimeBearer=owner
    ))
    assert ban["Member"]["Arn"] == banned, (
        f"CreateChannelBan reported member {ban['Member']['Arn']!r}, expected {banned!r}"
    )

    roster = [m["Member"]["Arn"] for m in _paginated(
        messaging.list_channel_memberships, "ChannelMemberships",
        ChannelArn=channel, ChimeBearer=owner,
    )]
    assert banned not in roster, f"the ban left {banned!r} in the membership roster {roster!r}"
    assert allowed in roster, f"the ban removed the wrong member; roster is {roster!r}"

    sent, sent_message = _error(
        messaging.send_channel_message, ChannelArn=channel, Content="sim2real-after-ban",
        Type="STANDARD", Persistence="PERSISTENT", ChimeBearer=banned,
        ClientRequestToken=uuid.uuid4().hex,
    )
    assert sent == "ForbiddenException", (
        f"a banned member's SendChannelMessage got {sent!r}, expected 'ForbiddenException'"
    )
    assert sent_message == _FORBIDDEN_BANNED, (
        f"a banned member's SendChannelMessage returned the message {sent_message!r}, "
        f"expected {_FORBIDDEN_BANNED!r}"
    )
    read, read_message = _error(
        messaging.list_channel_messages, ChannelArn=channel, ChimeBearer=banned
    )
    assert read == "ForbiddenException", (
        f"a banned member's ListChannelMessages got {read!r}, expected 'ForbiddenException'"
    )
    assert read_message == _FORBIDDEN_BANNED, (
        f"a banned member's ListChannelMessages returned the message {read_message!r}, "
        f"expected {_FORBIDDEN_BANNED!r}"
    )
    rejoin, rejoin_message = _error(
        messaging.create_channel_membership, ChannelArn=channel, MemberArn=banned,
        Type="DEFAULT", ChimeBearer=owner,
    )
    assert rejoin == "ForbiddenException", (
        f"re-adding a banned member got {rejoin!r}, expected 'ForbiddenException'"
    )
    assert rejoin_message == _FORBIDDEN_BANNED, (
        f"re-adding a banned member returned the message {rejoin_message!r}, "
        f"expected {_FORBIDDEN_BANNED!r}"
    )

    # Positive control: the unbanned member still writes, and the refused write left no trace.
    after = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-allowed-write", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=allowed, ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]
    contents = {m["MessageId"]: m.get("Content") for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=owner,
    )}
    assert set(contents) == {before, after}, (
        f"the channel holds {sorted(contents)!r}, expected exactly the pre-ban and allowed "
        f"messages {sorted([before, after])!r}"
    )
    assert "sim2real-after-ban" not in contents.values(), (
        f"the banned member's refused message was stored anyway: {sorted(contents.values())!r}"
    )

    messaging.delete_channel_ban(ChannelArn=channel, MemberArn=banned, ChimeBearer=owner)
    gone, gone_message = _error(
        messaging.describe_channel_ban, ChannelArn=channel, MemberArn=banned, ChimeBearer=owner
    )
    assert gone == "NotFoundException", (
        f"DescribeChannelBan after DeleteChannelBan got {gone!r}, expected 'NotFoundException'"
    )
    assert gone_message == _NOT_BANNED, (
        f"DescribeChannelBan after DeleteChannelBan returned the message {gone_message!r}, "
        f"expected {_NOT_BANNED!r}"
    )
    rejoined = messaging.create_channel_membership(
        ChannelArn=channel, MemberArn=banned, Type="DEFAULT", ChimeBearer=owner
    )
    assert rejoined["Member"]["Arn"] == banned, (
        f"after the ban was lifted the rejoin returned {rejoined['Member']['Arn']!r}, "
        f"expected {banned!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
