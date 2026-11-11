"""parameter-group-unknown-parameter-fails."""

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


CHECK = "parameter-group-unknown-parameter-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterParameterGroup rejects a parameter name the family does not define with
    InvalidParameterValue and its exact message and stores nothing, while the same call shape with
    a real parameter name succeeds."""
    rs = ctx.client("redshift")
    group_name = ctx.unique_name("sim2real-behav-rs-pgbad-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_cluster_parameter_group(ParameterGroupName=group_name), "ClusterParameterGroupNotFound"
    ))
    rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="behavioral fidelity unknown-parameter check",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    # Positive control: a real parameter name in the family is accepted and visibly applied.
    control = _retrying(lambda: rs.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "require_ssl", "ParameterValue": "true"}],
    ))
    assert control["ParameterGroupName"] == group_name, control
    control_params = {
        p["ParameterName"]: p
        for p in rs.describe_cluster_parameters(ParameterGroupName=group_name)["Parameters"]
    }
    assert control_params["require_ssl"]["ParameterValue"] == "true", control_params["require_ssl"]
    assert control_params["require_ssl"]["Source"] == "user", (
        f"the control modify must be applied with Source 'user', got "
        f"{control_params['require_ssl'].get('Source')!r}"
    )

    code, message = _error(lambda: rs.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "sim2real_behav_not_a_parameter", "ParameterValue": "1"}],
    ))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Could not find parameter with name: sim2real_behav_not_a_parameter", message

    after = {
        p["ParameterName"]: p
        for p in rs.describe_cluster_parameters(ParameterGroupName=group_name)["Parameters"]
    }
    assert "sim2real_behav_not_a_parameter" not in after, "the rejected parameter must not be stored"
    assert after["require_ssl"]["ParameterValue"] == "true", (
        "the rejected modify must not disturb the control parameter set earlier, got "
        f"{after['require_ssl'].get('ParameterValue')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
