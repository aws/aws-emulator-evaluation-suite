"""list-private-channels-requires-app-instance-admin-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-private-channels-requires-app-instance-admin-rejected"
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


def _listed(messaging, app_instance, bearer, privacy):
    out, token = [], None
    while True:
        page = messaging.list_channels(
            AppInstanceArn=app_instance, Privacy=privacy, ChimeBearer=bearer, MaxResults=2,
            **({"NextToken": token} if token else {}),
        )
        out.extend(c["ChannelArn"] for c in page["Channels"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A plain AppInstanceUser's ListChannels(Privacy=PRIVATE) fails with ForbiddenException and
    the exact message, and its PUBLIC listing omits the private channel; once the same user is an
    AppInstanceAdmin, the PRIVATE listing returns exactly that channel within 30 s."""
    identity = ctx.client("chime-sdk-identity", region=_REGION)
    messaging = ctx.client("chime-sdk-messaging", region=_REGION)

    app_instance = _app_instance(ctx, identity)
    owner = _user(ctx, identity, app_instance, "owner")
    plain = _user(ctx, identity, app_instance, "plain")

    private = messaging.create_channel(
        AppInstanceArn=app_instance,
        Name=ctx.unique_name("sim2real-behav-private-"),
        Mode="RESTRICTED",
        Privacy="PRIVATE",
        ChimeBearer=owner,
        ClientRequestToken=uuid.uuid4().hex,
    )["ChannelArn"]
    ctx.on_cleanup(lambda: messaging.delete_channel(ChannelArn=private, ChimeBearer=owner))

    refused, refused_message = _error(
        messaging.list_channels, AppInstanceArn=app_instance, Privacy="PRIVATE", ChimeBearer=plain
    )
    assert refused == "ForbiddenException", (
        f"a non-admin AppInstanceUser listing PRIVATE channels got {refused!r}, expected "
        f"'ForbiddenException'"
    )
    assert refused_message == _FORBIDDEN, (
        f"a non-admin AppInstanceUser listing PRIVATE channels returned the message "
        f"{refused_message!r}, "
        f"expected {_FORBIDDEN!r}"
    )

    # The same user can still enumerate PUBLIC channels: it is the Privacy filter that is gated,
    # not the operation.
    public_visible = _listed(messaging, app_instance, plain, "PUBLIC")
    assert private not in public_visible, (
        f"the PRIVATE channel {private!r} showed up in the PUBLIC listing {public_visible!r}"
    )

    # Positive control: promote the SAME bearer and retry the SAME call.
    identity.create_app_instance_admin(
        AppInstanceAdminArn=plain, AppInstanceArn=app_instance
    )
    ctx.on_cleanup(lambda: identity.delete_app_instance_admin(
        AppInstanceAdminArn=plain, AppInstanceArn=app_instance
    ))

    # The admin record is created in the identity plane and read by the messaging plane, so allow
    # it to propagate — tolerating ONLY the refusal we are here to see lifted.
    now_visible, last = None, None
    for _ in range(15):
        try:
            now_visible = _listed(messaging, app_instance, plain, "PRIVATE")
            break
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "ForbiddenException":
                raise
            last = code
            time.sleep(2)
    assert now_visible is not None, (
        f"ListChannels(Privacy=PRIVATE) was still {last!r} 30s after {plain!r} became an "
        f"AppInstanceAdmin"
    )
    assert now_visible == [private], (
        f"as an AppInstanceAdmin the PRIVATE listing is {now_visible!r}, expected exactly the one "
        f"private channel {private!r} this check created in its own AppInstance"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
