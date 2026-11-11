"""parameter-group-lifecycle."""

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


def _message_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message", "")
    return str(exc)


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
    """Call *fn*; return (AWS error code, message), or ("OK", "") if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc), _message_of(exc)
    return "OK", ""


def _probe_codes(cases):
    """{label: callable} -> {label: (error-code-or-"OK", message)}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}


def _wait_until(probe, done, timeout_s=600, interval_s=15, what="condition"):
    deadline = time.time() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"
PARAM_FAMILY = "redshift-1.0"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")

CHECK = "parameter-group-lifecycle"
GROUP = 'parameter-group'
SERVICES = ['redshift']


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Parameter groups: create -> modify (user override) -> reset (back to engine default) -> delete."""
    rs = ctx.client("redshift")
    group_name = ctx.unique_name("sim2real-behav-rs-pg-")
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rs.delete_cluster_parameter_group(ParameterGroupName=group_name),
        "ClusterParameterGroupNotFound"))
    created = rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="behavioral fidelity check group",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )["ClusterParameterGroup"]
    assert created["ParameterGroupName"] == group_name, (
        f"expected ParameterGroupName={group_name!r}, got {created['ParameterGroupName']!r}"
    )
    assert created["ParameterGroupFamily"] == PARAM_FAMILY, (
        f"expected ParameterGroupFamily={PARAM_FAMILY!r}, got {created['ParameterGroupFamily']!r}"
    )

    described = rs.describe_cluster_parameter_groups(ParameterGroupName=group_name)["ParameterGroups"]
    assert len(described) == 1, f"expected exactly one group, got {described}"
    assert described[0]["Description"] == "behavioral fidelity check group", (
        f"expected Description='behavioral fidelity check group', got {described[0]['Description']!r}"
    )

    defaults = rs.describe_default_cluster_parameters(
        ParameterGroupFamily=PARAM_FAMILY
    )["DefaultClusterParameters"]["Parameters"]
    default_require_ssl = next(p for p in defaults if p["ParameterName"] == "require_ssl")

    before = rs.describe_cluster_parameters(ParameterGroupName=group_name)["Parameters"]
    require_ssl_before = next(p for p in before if p["ParameterName"] == "require_ssl")
    assert require_ssl_before["Source"] == "engine-default", require_ssl_before
    assert require_ssl_before["ParameterValue"] == default_require_ssl["ParameterValue"], (
        f"expected freshly-created group's require_ssl={default_require_ssl['ParameterValue']!r} "
        f"(the engine default), got {require_ssl_before['ParameterValue']!r}"
    )

    modify_resp = rs.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "require_ssl", "ParameterValue": "true"}],
    )
    assert modify_resp["ParameterGroupName"] == group_name, (
        f"expected ModifyClusterParameterGroup to echo ParameterGroupName={group_name!r}, "
        f"got {modify_resp['ParameterGroupName']!r}"
    )

    after = rs.describe_cluster_parameters(ParameterGroupName=group_name)["Parameters"]
    require_ssl_after = next(p for p in after if p["ParameterName"] == "require_ssl")
    assert require_ssl_after["ParameterValue"] == "true", require_ssl_after
    assert require_ssl_after["Source"] == "user", (
        f"an explicitly set parameter must be sourced to 'user', got {require_ssl_after['Source']}"
    )

    rs.reset_cluster_parameter_group(ParameterGroupName=group_name, ResetAllParameters=True)
    reset_value = _wait_until(
        lambda: next(
            p for p in rs.describe_cluster_parameters(ParameterGroupName=group_name)["Parameters"]
            if p["ParameterName"] == "require_ssl"
        ),
        lambda p: p["Source"] == "engine-default",
        timeout_s=120,
        interval_s=10,
        what="require_ssl to fall back to the engine default after reset",
    )
    assert reset_value["ParameterValue"] == default_require_ssl["ParameterValue"], reset_value

    rs.delete_cluster_parameter_group(ParameterGroupName=group_name)
    code, message = _err(lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=group_name))
    assert code == "ClusterParameterGroupNotFound", f"expected ClusterParameterGroupNotFound, got {code}"
    expected = f"ClusterParameterGroup {group_name} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    modify_code, modify_message = _err(lambda: rs.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "require_ssl", "ParameterValue": "true"}],
    ))
    assert modify_code == "ClusterParameterGroupNotFound", (
        f"a mutation on the just-deleted group must also fail with ClusterParameterGroupNotFound, "
        f"got {modify_code}"
    )
    assert modify_message == "Parameter group does not exist", (
        f"expected message 'Parameter group does not exist', got {modify_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
