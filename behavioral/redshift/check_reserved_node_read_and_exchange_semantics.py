"""reserved-node-read-and-exchange-semantics."""

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

CHECK = "reserved-node-read-and-exchange-semantics"
GROUP = 'reserved-nodes'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reserved-node catalog reads return well-formed offerings, and exchange operations validate
    their inputs (including the 'supply at least one filter' rule) before doing anything."""
    rs = ctx.client("redshift")
    offerings = _retrying(
        lambda: rs.describe_reserved_node_offerings(MaxRecords=20)
    )["ReservedNodeOfferings"]
    assert isinstance(offerings, list), f"ReservedNodeOfferings was not a list: {offerings!r}"
    for offering in offerings[:5]:
        assert offering["ReservedNodeOfferingId"], offering
        assert offering["NodeType"], offering
        assert offering["Duration"] > 0, offering

    owned = _retrying(lambda: rs.describe_reserved_nodes(MaxRecords=20))["ReservedNodes"]
    assert isinstance(owned, list), f"ReservedNodes was not a list: {owned!r}"

    missing_node = "sim2real-behav-missing-reserved-node"
    missing_cluster = ctx.unique_name("sim2real-behav-rs-rncl-")
    cases = {
        "DescribeReservedNodeExchangeStatus(no-filter)": lambda: (
            rs.describe_reserved_node_exchange_status(MaxRecords=20)
        ),
        "GetReservedNodeExchangeOfferings": lambda: rs.get_reserved_node_exchange_offerings(
            ReservedNodeId=missing_node
        ),
        "AcceptReservedNodeExchange": lambda: rs.accept_reserved_node_exchange(
            ReservedNodeId=missing_node, TargetReservedNodeOfferingId="sim2real-behav-missing-offering"
        ),
        "GetReservedNodeExchangeConfigurationOptions": lambda: (
            rs.get_reserved_node_exchange_configuration_options(
                ActionType="resize-cluster", ClusterIdentifier=missing_cluster
            )
        ),
    }
    observed = _probe_codes(cases)
    expected = {
        # Neither ReservedNodeId nor ReservedNodeExchangeRequestId supplied.
        "DescribeReservedNodeExchangeStatus(no-filter)": "InvalidParameterCombination",
        # Reserved-node ids are validated for FORMAT before any lookup happens,
        # so a non-UUID id is a parameter error rather than a not-found.
        "GetReservedNodeExchangeOfferings": "InvalidParameterValue",
        "AcceptReservedNodeExchange": "InvalidParameterValue",
        "GetReservedNodeExchangeConfigurationOptions": "ClusterNotFound",
    }
    assert observed == expected, f"reserved-node contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
