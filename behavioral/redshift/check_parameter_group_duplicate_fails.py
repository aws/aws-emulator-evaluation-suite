"""parameter-group-duplicate-fails."""

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


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")


def _delete_absent_ok(delete, gone_code):
    """Teardown: the parameter group delete is synchronous; one that was never created answers *gone_code*."""
    try:
        delete()
    except ClientError as exc:
        if _code_of(exc) != gone_code:
            raise


CHECK = "parameter-group-duplicate-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating a parameter group name in use is rejected with ClusterParameterGroupAlreadyExists
    and its exact message without overwriting the original; once it is deleted (NotFound with its
    exact message) the identical call succeeds again."""
    rs = ctx.client("redshift")
    group_name = ctx.unique_name("sim2real-behav-rs-pgdup-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_cluster_parameter_group(ParameterGroupName=group_name), "ClusterParameterGroupNotFound"
    ))
    created = rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="original description",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ClusterParameterGroup"]
    assert created["ParameterGroupName"] == group_name, created

    code, message = _error(lambda: rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="overwritten description",
    ))
    assert code == "ClusterParameterGroupAlreadyExists", (
        f"expected ClusterParameterGroupAlreadyExists, got {code}"
    )
    assert message == f"Parameter group {group_name} already exists", message

    described = rs.describe_cluster_parameter_groups(ParameterGroupName=group_name)["ParameterGroups"][0]
    assert described["Description"] == "original description", "the losing create must not mutate the group"

    # restore: delete the original (independent not-found read proves it is gone), then the
    # identical create must succeed again.
    rs.delete_cluster_parameter_group(ParameterGroupName=group_name)
    gone_code, gone_message = _error(lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=group_name))
    assert gone_code == "ClusterParameterGroupNotFound", (
        f"expected ClusterParameterGroupNotFound after delete, got {gone_code}"
    )
    assert gone_message == f"ClusterParameterGroup {group_name} not found.", gone_message

    rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="original description",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    restored = rs.describe_cluster_parameter_groups(ParameterGroupName=group_name)["ParameterGroups"][0]
    assert restored["Description"] == "original description", restored


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
