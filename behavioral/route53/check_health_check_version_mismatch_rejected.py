"""health-check-version-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-version-mismatch-rejected"
GROUP = "health-check"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHealthCheck is rejected with HealthCheckVersionMismatch when the
    supplied HealthCheckVersion is stale, the config is left unchanged by the
    rejected call, and an update using the correct version succeeds (control)."""
    route53 = ctx.client("route53")

    created = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-hc-"),
        HealthCheckConfig={
            # a name under the reserved .invalid TLD never resolves, so no host is probed
            "FullyQualifiedDomainName": f"{ctx.unique_name('sim2real-hc').lower()}.invalid",
            "Port": 80,
            "Type": "TCP",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = created["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_health_check(HealthCheckId=hc_id))
    current_version = created["HealthCheck"]["HealthCheckVersion"]

    # break exactly one thing: update with a HealthCheckVersion that does not match
    stale_version = current_version + 999
    err = _client_error(
        lambda: route53.update_health_check(
            HealthCheckId=hc_id,
            HealthCheckVersion=stale_version,
            FailureThreshold=7,
        )
    )
    assert err["Code"] == "HealthCheckVersionMismatch", (
        f"expected HealthCheckVersionMismatch for stale version {stale_version}, got {err}"
    )
    assert err["Message"] == (
        f"Health check with id {hc_id} has version {current_version}, "
        f"but expected to have version {stale_version}. Could not proceed with update."
    ), err

    # effect absent: the config and version are unchanged by the rejected call
    unchanged = route53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert unchanged["HealthCheckConfig"]["FailureThreshold"] == 3, (
        f"expected FailureThreshold unchanged at 3 after rejected update, "
        f"got {unchanged['HealthCheckConfig']['FailureThreshold']}"
    )
    assert unchanged["HealthCheckVersion"] == current_version, (
        f"expected HealthCheckVersion unchanged at {current_version} after rejected "
        f"update, got {unchanged['HealthCheckVersion']}"
    )

    # positive control: the identical update with the correct version succeeds
    updated = route53.update_health_check(
        HealthCheckId=hc_id,
        HealthCheckVersion=current_version,
        FailureThreshold=7,
    )["HealthCheck"]
    assert updated["HealthCheckConfig"]["FailureThreshold"] == 7, (
        f"expected FailureThreshold 7 after correct-version update, "
        f"got {updated['HealthCheckConfig']['FailureThreshold']}"
    )
    assert updated["HealthCheckVersion"] > current_version, (
        f"expected HealthCheckVersion to advance past {current_version}, "
        f"got {updated['HealthCheckVersion']}"
    )

    refetched = route53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert refetched["HealthCheckConfig"]["FailureThreshold"] == 7, (
        f"expected independent read to show FailureThreshold 7, "
        f"got {refetched['HealthCheckConfig']['FailureThreshold']}"
    )


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
