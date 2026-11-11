"""resource-policy-ops-semantics."""

from __future__ import annotations

import json
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

CHECK = "resource-policy-ops-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Resource-policy operations validate the target resource ARN up front: an ARN that does not
    identify a policy-attachable Redshift resource is rejected as a parameter error, and no policy
    is created or returned."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]
    target = f"arn:aws:redshift:{ctx.region}:{account}:datashare:11111111-1111-1111-1111-111111111111/sim2real_behav"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": account},
            "Action": "redshift:DescribeClusters",
            "Resource": "*",
        }],
    })
    cases = {
        "GetResourcePolicy": lambda: rs.get_resource_policy(ResourceArn=target),
        "PutResourcePolicy": lambda: rs.put_resource_policy(ResourceArn=target, Policy=policy),
        "DeleteResourcePolicy": lambda: rs.delete_resource_policy(ResourceArn=target),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "InvalidParameterValue")
    assert observed == expected, f"resource-policy contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
