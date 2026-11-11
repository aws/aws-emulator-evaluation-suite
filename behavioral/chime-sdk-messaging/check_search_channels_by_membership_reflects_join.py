"""search-channels-by-membership-reflects-join."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "search-channels-by-membership-reflects-join"
GROUP = "membership"
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


def _search(messaging, bearer, members):
    """Channels whose membership INCLUDES every arn in *members*, as this bearer sees them.

    Scoped to the searching bearer's own AppInstance, and every member arn is one this check
    minted, so the result set is fully owned by this run.
    """
    out, token = [], None
    while True:
        page = messaging.search_channels(
            ChimeBearer=bearer, MaxResults=2,
            Fields=[{"Key": "MEMBERS", "Values": members, "Operator": "INCLUDES"}],
            **({"NextToken": token} if token else {}),
        )
        out.extend(c["ChannelArn"] for c in page["Channels"])
        token = page.get("NextToken")
        if not token:
            return out


def _await(predicate, what, attempts=15, delay=2):
    for _ in range(attempts):
        value = predicate()
        if value is not None:
            return value
        time.sleep(delay)
    raise AssertionError(f"{what} did not hold within {attempts * delay}s")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A MEMBERS=INCLUDES SearchChannels omits a channel the user has not joined, returns it after
    the join (also for both members at once), and drops it after the user leaves while the owner
    still finds it."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    joiner = _user(ctx, identity, app_instance, "joiner")

    channel = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-ch-"),
        Mode="UNRESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=channel, ChimeBearer=owner))

    # The creator is a member, so the same query already finds the channel for the OWNER. That is
    # the positive control for the query itself: an empty result below must mean "not a member",
    # not "search is broken".
    by_owner = _await(
        lambda: _search(messaging, owner, [owner]) or None,
        f"SearchChannels(MEMBERS INCLUDES {owner!r}) never found the channel the owner created",
    )
    assert by_owner == [channel], (
        f"the owner's membership search returned {by_owner!r}, expected exactly {channel!r}"
    )

    before = _search(messaging, joiner, [joiner])
    assert before == [], (
        f"a user who has joined nothing in its own fresh AppInstance already matches "
        f"{before!r}"
    )

    messaging.create_channel_membership(
        ChannelArn=channel, MemberArn=joiner, Type="DEFAULT", ChimeBearer=owner
    )

    after = _await(
        lambda: _search(messaging, joiner, [joiner]) or None,
        f"the join of {joiner!r} never showed up in a MEMBERS-scoped SearchChannels",
    )
    assert after == [channel], (
        f"after joining, the membership search returned {after!r}, expected exactly {channel!r}"
    )

    # Both members at once: the INCLUDES filter is a conjunction over the roster.
    both = _search(messaging, owner, [owner, joiner])
    assert both == [channel], (
        f"searching for channels containing BOTH members returned {both!r}, expected {channel!r}"
    )

    messaging.delete_channel_membership(
        ChannelArn=channel, MemberArn=joiner, ChimeBearer=owner
    )
    gone = _await(
        lambda: [] if _search(messaging, owner, [owner, joiner]) == [] else None,
        f"the channel still matched a search requiring the departed member {joiner!r}",
    )
    assert gone == []
    assert _search(messaging, owner, [owner]) == [channel], (
        "removing one member dropped the channel from the OWNER's membership search too"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
