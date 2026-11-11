"""endpoint-access-ops-not-found-semantics."""

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

CHECK = "endpoint-access-ops-not-found-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

OTHER_ACCOUNT = "111122223333"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Redshift-managed VPC endpoint operations distinguish an unknown ENDPOINT from an unknown CLUSTER."""
    rs = ctx.client("redshift")
    missing_endpoint = ctx.unique_name("sim2real-behav-rs-ep-")
    missing_cluster = ctx.unique_name("sim2real-behav-rs-epcl-")
    cases = {
        "DescribeEndpointAccess": lambda: rs.describe_endpoint_access(EndpointName=missing_endpoint),
        "DeleteEndpointAccess": lambda: rs.delete_endpoint_access(EndpointName=missing_endpoint),
        "ModifyEndpointAccess": lambda: rs.modify_endpoint_access(EndpointName=missing_endpoint),
        "CreateEndpointAccess": lambda: rs.create_endpoint_access(
            EndpointName=missing_endpoint,
            SubnetGroupName=ctx.unique_name("sim2real-behav-rs-epsng-"),
            ClusterIdentifier=missing_cluster,
        ),
        "AuthorizeEndpointAccess": lambda: rs.authorize_endpoint_access(
            ClusterIdentifier=missing_cluster, Account=OTHER_ACCOUNT
        ),
        "RevokeEndpointAccess": lambda: rs.revoke_endpoint_access(
            ClusterIdentifier=missing_cluster, Account=OTHER_ACCOUNT
        ),
        "DescribeEndpointAuthorization": lambda: rs.describe_endpoint_authorization(
            ClusterIdentifier=missing_cluster
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "EndpointNotFound")
    # Precedence: real AWS resolves the SUBNET GROUP before the cluster on CreateEndpointAccess;
    # no precedence is documented, so ClusterNotFound is accepted there too.
    expected["CreateEndpointAccess"] = "ClusterSubnetGroupNotFoundFault"
    expected["AuthorizeEndpointAccess"] = "ClusterNotFound"
    expected["RevokeEndpointAccess"] = "ClusterNotFound"
    expected["DescribeEndpointAuthorization"] = "ClusterNotFound"
    assert observed == expected or observed == {
        **expected,
        "CreateEndpointAccess": "ClusterNotFound",
    }, f"endpoint-access contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
