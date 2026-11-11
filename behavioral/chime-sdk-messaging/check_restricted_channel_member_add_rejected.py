"""restricted-channel-member-add-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "restricted-channel-member-add-rejected"
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


def _roster(messaging, channel, bearer):
    out, token = [], None
    while True:
        page = messaging.list_channel_memberships(
            ChannelArn=channel, ChimeBearer=bearer, MaxResults=2,
            **({"NextToken": token} if token else {}),
        )
        out.extend(m["Member"]["Arn"] for m in page["ChannelMemberships"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a RESTRICTED channel a plain member's CreateChannelMembership fails with
    ForbiddenException and the exact message and the roster stays owner and member; in an
    UNRESTRICTED channel the same member's same call adds the invitee."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    member = _user(ctx, identity, app_instance, "member")
    invitee = _user(ctx, identity, app_instance, "invitee")

    restricted = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-restricted-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=restricted, ChimeBearer=owner))
    messaging.create_channel_membership(
        ChannelArn=restricted, MemberArn=member, Type="DEFAULT", ChimeBearer=owner
    )

    refused, refused_message = _error(
        messaging.create_channel_membership, ChannelArn=restricted, MemberArn=invitee,
        Type="DEFAULT", ChimeBearer=member,
    )
    assert refused == "ForbiddenException", (
        f"a non-moderator adding a member to a RESTRICTED channel got {refused!r}, expected "
        f"'ForbiddenException'"
    )
    assert refused_message == _FORBIDDEN, (
        f"a non-moderator adding a member to a RESTRICTED channel returned the message "
        f"{refused_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )
    roster = _roster(messaging, restricted, owner)
    assert invitee not in roster, (
        f"the refused add put {invitee!r} into the RESTRICTED channel's roster {roster!r}"
    )
    assert sorted(roster) == sorted([owner, member]), (
        f"the RESTRICTED channel's roster is {sorted(roster)!r}, expected the creator and the one "
        f"invited member"
    )

    # Positive control: the same member, the same call, on an UNRESTRICTED channel.
    unrestricted = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-unrestricted-"),
        Mode="UNRESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=unrestricted, ChimeBearer=owner))
    messaging.create_channel_membership(
        ChannelArn=unrestricted, MemberArn=member, Type="DEFAULT", ChimeBearer=owner
    )

    added = messaging.create_channel_membership(
        ChannelArn=unrestricted, MemberArn=invitee, Type="DEFAULT", ChimeBearer=member
    )
    assert added["Member"]["Arn"] == invitee, (
        f"the UNRESTRICTED add reported member {added['Member']['Arn']!r}, expected {invitee!r}"
    )
    open_roster = _roster(messaging, unrestricted, owner)
    assert invitee in open_roster, (
        f"the UNRESTRICTED add is missing from the roster {open_roster!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
