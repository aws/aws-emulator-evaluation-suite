"""health-check-lifecycle."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "health-check-lifecycle"
GROUP = 'health-check'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _health_check_fqdn(ctx):
    """A name under the reserved .invalid TLD: it never resolves, so the health check probes no host."""
    return f"{ctx.unique_name('sim2real-behav-hc').lower()}.invalid"


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")



def _delete_health_check_if_present(r53, hc_id):
    """Teardown: the run deletes the health check itself, so a not-found here is success."""
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create->Get->Update (version bump)->stale-version rejected (effect absent, then
    restored with the correct version)->Delete->Get fails->mutation on the dead id fails."""
    r53 = ctx.client("route53")
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "FullyQualifiedDomainName": _health_check_fqdn(ctx),
            "Port": 80,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: _delete_health_check_if_present(r53, i))
    r53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=hc_id,
        AddTags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-hc")}],
    )
    initial_version = resp["HealthCheck"]["HealthCheckVersion"]

    updated = r53.update_health_check(
        HealthCheckId=hc_id, HealthCheckVersion=initial_version, ResourcePath="/healthz"
    )
    current_version = updated["HealthCheck"]["HealthCheckVersion"]
    assert current_version == initial_version + 1, (current_version, initial_version)
    assert updated["HealthCheck"]["HealthCheckConfig"]["ResourcePath"] == "/healthz", (
        updated["HealthCheck"]["HealthCheckConfig"]
    )

    # break exactly one thing: reuse the now-stale version
    err = _client_error(
        lambda: r53.update_health_check(
            HealthCheckId=hc_id, HealthCheckVersion=initial_version, ResourcePath="/other"
        )
    )
    assert err["Code"] == "HealthCheckVersionMismatch", err
    assert err["Message"] == (
        f"Health check with id {hc_id} has version {current_version}, "
        f"but expected to have version {initial_version}. Could not proceed with update."
    ), err

    # effect absent: the rejected call moved neither the version nor the config
    unchanged = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert unchanged["HealthCheckVersion"] == current_version, (
        unchanged["HealthCheckVersion"], current_version
    )
    assert unchanged["HealthCheckConfig"]["ResourcePath"] == "/healthz", (
        unchanged["HealthCheckConfig"]
    )

    # restore: the identical call with the correct (current) version succeeds
    restored = r53.update_health_check(
        HealthCheckId=hc_id, HealthCheckVersion=current_version, ResourcePath="/other"
    )["HealthCheck"]
    assert restored["HealthCheckVersion"] == current_version + 1, (
        restored["HealthCheckVersion"], current_version
    )
    assert restored["HealthCheckConfig"]["ResourcePath"] == "/other", (
        restored["HealthCheckConfig"]
    )

    r53.delete_health_check(HealthCheckId=hc_id)
    err = _client_error(lambda: r53.get_health_check(HealthCheckId=hc_id))
    assert err["Code"] == "NoSuchHealthCheck", err
    assert err["Message"] == f"A health check with id {hc_id} does not exist.", err

    # a mutation on the dead id also fails, with the same specific not-found code
    err = _client_error(
        lambda: r53.update_health_check(
            HealthCheckId=hc_id, HealthCheckVersion=current_version + 1, ResourcePath="/dead"
        )
    )
    assert err["Code"] == "NoSuchHealthCheck", err
    assert err["Message"] == f"A health check with id {hc_id} does not exist.", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
