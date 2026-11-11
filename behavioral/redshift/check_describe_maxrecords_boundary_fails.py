"""describe-maxrecords-boundary-fails."""

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

CHECK = "describe-maxrecords-boundary-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MaxRecords=20 is accepted and 1 and 0 are rejected below the minimum, while 101, above the
    documented maximum of 100, is accepted: only the lower bound is enforced."""
    rs = ctx.client("redshift")
    cases = {
        # Positive controls: an in-bounds MaxRecords must succeed on the SAME operation as each
        # below-minimum negative, so a target that rejects every call to that operation (not just
        # the out-of-range one) cannot be mistaken for one that enforces the boundary correctly.
        "DescribeClusters(MaxRecords=20)": lambda: rs.describe_clusters(MaxRecords=20),
        "DescribeClusterParameterGroups(MaxRecords=20)": lambda: rs.describe_cluster_parameter_groups(
            MaxRecords=20
        ),
        "DescribeClusters(MaxRecords=1)": lambda: rs.describe_clusters(MaxRecords=1),
        "DescribeClusterParameterGroups(MaxRecords=0)": lambda: rs.describe_cluster_parameter_groups(
            MaxRecords=0
        ),
        "DescribeClusterSnapshots(MaxRecords=101)": lambda: rs.describe_cluster_snapshots(MaxRecords=101),
    }
    observed = _probe_codes(cases)
    expected = {
        "DescribeClusters(MaxRecords=20)": "OK",
        "DescribeClusterParameterGroups(MaxRecords=20)": "OK",
        "DescribeClusters(MaxRecords=1)": "InvalidParameterValue",
        "DescribeClusterParameterGroups(MaxRecords=0)": "InvalidParameterValue",
        "DescribeClusterSnapshots(MaxRecords=101)": "OK",
    }
    assert observed == expected, f"MaxRecords boundary drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
