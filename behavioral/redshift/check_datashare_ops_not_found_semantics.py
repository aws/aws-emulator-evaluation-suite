"""datashare-ops-not-found-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "datashare-ops-not-found-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

OTHER_ACCOUNT = "111122223333"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Datashare operations validate the datashare/namespace ARN itself, with codes distinct from the
    cluster not-found family."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]
    share_arn = f"arn:aws:redshift:{ctx.region}:{account}:datashare:11111111-1111-1111-1111-111111111111/sim2real_behav"
    namespace_arn = f"arn:aws:redshift:{ctx.region}:{account}:namespace:11111111-1111-1111-1111-111111111111"
    cases = {
        "DescribeDataShares": lambda: rs.describe_data_shares(DataShareArn=share_arn),
        "DescribeDataSharesForConsumer": lambda: rs.describe_data_shares_for_consumer(
            ConsumerArn=namespace_arn
        ),
        "DescribeDataSharesForProducer": lambda: rs.describe_data_shares_for_producer(
            ProducerArn=namespace_arn
        ),
        "AuthorizeDataShare": lambda: rs.authorize_data_share(
            DataShareArn=share_arn, ConsumerIdentifier=OTHER_ACCOUNT
        ),
        "DeauthorizeDataShare": lambda: rs.deauthorize_data_share(
            DataShareArn=share_arn, ConsumerIdentifier=OTHER_ACCOUNT
        ),
        "AssociateDataShareConsumer": lambda: rs.associate_data_share_consumer(
            DataShareArn=share_arn, AssociateEntireAccount=True
        ),
        "DisassociateDataShareConsumer": lambda: rs.disassociate_data_share_consumer(
            DataShareArn=share_arn, DisassociateEntireAccount=True
        ),
        "RejectDataShare": lambda: rs.reject_data_share(DataShareArn=share_arn),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "InvalidDataShareFault")
    expected["DescribeDataSharesForConsumer"] = "InvalidNamespaceFault"
    expected["DescribeDataSharesForProducer"] = "InvalidNamespaceFault"
    assert observed == expected, f"datashare contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
