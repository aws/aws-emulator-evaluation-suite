"""list-public-keys-shape-and-time-range-validation."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected list_public_keys to reject the inverted time range, but it succeeded")


CHECK = "list-public-keys-shape-and-time-range-validation"
GROUP = 'digest'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPublicKeys returns the digest-signing key list, and rejects an inverted
    time window with InvalidTimeRangeException."""
    ct = ctx.client("cloudtrail")
    now = datetime.datetime.now(datetime.timezone.utc)
    earlier = now - datetime.timedelta(days=1)

    resp = ct.list_public_keys(StartTime=earlier, EndTime=now)
    keys = resp.get("PublicKeyList")
    assert isinstance(keys, list), resp
    assert len(keys) >= 1, f"expected at least one CloudTrail digest-signing public key in the last day, got {resp}"
    for key in keys:
        assert key.get("Value"), key
        assert key.get("Fingerprint"), key

    err, message = _error(lambda: ct.list_public_keys(StartTime=now, EndTime=earlier))
    assert err == "InvalidTimeRangeException", err
    assert message == "Invalid input parameter! Start time is after end time", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
