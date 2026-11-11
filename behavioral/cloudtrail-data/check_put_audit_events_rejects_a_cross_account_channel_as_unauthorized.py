"""put-audit-events-rejects-a-cross-account-channel-as-unauthorized."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-rejects-a-cross-account-channel-as-unauthorized"
GROUP = 'audit-event-ingestion'
SERVICES = ['cloudtrail-data']

# RFC 5737-style AWS documentation account ids: reserved for examples, so a channel ARN built
# from one is guaranteed not to belong to this account and guaranteed not to be probed for real.
_FOREIGN_ACCOUNTS = ("111122223333", "444455556666")


def _error(fn):
    """(Error.Code, Error.Message, HTTP status) for the ClientError fn() raises. A SUCCESS raises
    rather than returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _event() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "eventData": json.dumps(
            {
                "version": "1.0",
                "userIdentity": {"type": "CustomIdentity", "principalId": "sim2real-behav"},
                "eventSource": "sim2real.behavioral",
                "eventName": "Sim2RealProbeEvent",
                "eventTime": "2026-01-01T00:00:00Z",
                "UID": str(uuid.uuid4()),
            }
        ),
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A channel ARN in a foreign account is refused with AccessDeniedException (HTTP 403) naming the action
    and the ARN and never "could not be found", while the same id in the caller's account gets
    ChannelNotFound (HTTP 400) with the exact message: cross-account existence is not observable.
    """
    ctd = ctx.client("cloudtrail-data")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account not in _FOREIGN_ACCOUNTS, (
        f"this account is {account!r}, which collides with the reserved documentation ids "
        f"{_FOREIGN_ACCOUNTS!r} this check builds its foreign ARNs from"
    )
    channel_id = str(uuid.uuid4())
    batch = [_event()]

    for foreign in _FOREIGN_ACCOUNTS:
        arn = f"arn:aws:cloudtrail:{ctx.region}:{foreign}:channel/{channel_id}"
        code, message, status = _error(
            lambda a=arn: ctd.put_audit_events(channelArn=a, auditEvents=batch)
        )
        assert code == "AccessDeniedException", (
            f"a channel ARN in account {foreign!r} raised {code!r} ({message!r}), "
            "expected AccessDeniedException"
        )
        assert status == 403, f"expected HTTP 403 for a foreign channel ARN, got {status!r}"
        assert "cloudtrail-data:PutAuditEvents" in message, (
            f"the denial does not name the action it refused: {message!r}"
        )
        assert arn in message, f"the denial does not name the resource it refused: {message!r}"
        assert "could not be found" not in message, (
            f"the denial leaks a resolution verdict for another account's channel: {message!r}"
        )

    # Positive control: the same id and the same payload under THIS account's segment get past
    # authorization and reach resolution, so the 403 above is about the account and not about a
    # channel that happens to be absent everywhere.
    mine = f"arn:aws:cloudtrail:{ctx.region}:{account}:channel/{channel_id}"
    code, message, status = _error(
        lambda: ctd.put_audit_events(channelArn=mine, auditEvents=batch)
    )
    assert code == "ChannelNotFound", (
        f"an absent channel in THIS account raised {code!r} ({message!r}), "
        "expected ChannelNotFound"
    )
    assert status == 400, f"expected HTTP 400 for an absent in-account channel, got {status!r}"
    assert message == f"The channel {mine} could not be found.", (
        f"unexpected resolution message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
