"""send-message-token-reuse-new-content-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "send-message-token-reuse-new-content-rejected"
GROUP = "data-plane"
SERVICES = ["chime-sdk-messaging"]

# chime-sdk-messaging is offered in us-east-1 and eu-central-1 only, and a channel lives in the
# region of the AppInstance that owns it.
_REGION = "us-east-1"
_TOKEN_CONFLICT = "The provided ClientRequestToken is already associated with an existing resource."


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with different content fails with ConflictException and the
    exact message and the channel keeps only the original body; the same content under a fresh token
    is stored."""
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
    original = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-first-body", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=sender, ClientRequestToken=token,
    )["MessageId"]

    conflict, conflict_message = _error(
        messaging.send_channel_message, ChannelArn=channel, Content="sim2real-second-body",
        Type="STANDARD", Persistence="PERSISTENT", ChimeBearer=sender, ClientRequestToken=token,
    )
    assert conflict == "ConflictException", (
        f"reusing a ClientRequestToken with new content got {conflict!r}, "
        f"expected 'ConflictException'"
    )
    assert conflict_message == _TOKEN_CONFLICT, (
        f"reusing a ClientRequestToken with new content returned the message {conflict_message!r}, "
        f"expected {_TOKEN_CONFLICT!r}"
    )

    stored = {m["MessageId"]: m.get("Content") for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=sender
    )}
    assert set(stored) == {original}, (
        f"the rejected send changed the channel: it holds {sorted(stored)!r}, expected only "
        f"{original!r}"
    )
    assert stored[original] == "sim2real-first-body", (
        f"the rejected send overwrote the original body with {stored[original]!r}"
    )

    # Positive control: the rejected CONTENT is fine — only the reused token was not.
    accepted = messaging.send_channel_message(
        ChannelArn=channel, Content="sim2real-second-body", Type="STANDARD",
        Persistence="PERSISTENT", ChimeBearer=sender, ClientRequestToken=uuid.uuid4().hex,
    )["MessageId"]
    final = {m["MessageId"]: m.get("Content") for m in _paginated(
        messaging.list_channel_messages, "ChannelMessages", ChannelArn=channel, ChimeBearer=sender
    )}
    assert set(final) == {original, accepted}, (
        f"after the retry under a fresh token the channel holds {sorted(final)!r}, expected "
        f"{sorted([original, accepted])!r}"
    )
    assert final[accepted] == "sim2real-second-body", (
        f"the freshly tokenised retry stored {final[accepted]!r}, expected 'sim2real-second-body'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
