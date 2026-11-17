"""calculated-health-check-duplicate-child-ids-rejected."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculated-health-check-duplicate-child-ids-rejected"
GROUP = "health-check"
SERVICES = ["route53"]

_REFUSAL = (
    "InvalidInput",
    "Calculated health checks must not have duplicate child health check IDs.",
)


def _caller_reference() -> str:
    return f"sim2real-cr-{secrets.token_hex(12)}"


def _leaf_health_check(ctx, r53) -> str:
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "Type": "HTTP",
            "FullyQualifiedDomainName": ctx.unique_name("sim2real-behav-leaf") + ".example.com",
            "Port": 80,
            "ResourcePath": "/",
        },
    )
    leaf_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_health_check(HealthCheckId=leaf_id))
    return leaf_id


def _expect_error(call):
    """Call `call`, require a ClientError, and return (code, message).

    Raises on an unexpected SUCCESS rather than a falsy sentinel, so an over-permissive target
    cannot be mistaken for a mere code mismatch.
    """
    try:
        result = call()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the create to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Listing the same child health check ID twice in a CALCULATED health check is refused,
    while the identical pair of distinct child IDs is accepted.
    """
    r53 = ctx.client("route53")
    leaf_a = _leaf_health_check(ctx, r53)
    leaf_b = _leaf_health_check(ctx, r53)

    # ---- the refusal: the same child ID listed twice -----------------------------------------
    code, message = _expect_error(lambda: r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "Type": "CALCULATED",
            "HealthThreshold": 0,
            "ChildHealthChecks": [leaf_a, leaf_a],
        },
    ))
    assert (code, message) == _REFUSAL, (
        f"a CALCULATED health check listing one child ID twice must be refused with "
        f"{_REFUSAL!r}, got {(code, message)!r}"
    )

    # ---- effect absent: nothing was created for the refused request --------------------------
    paginator = r53.get_paginator("list_health_checks")
    all_ids = {hc["Id"] for page in paginator.paginate() for hc in page["HealthChecks"]}
    assert all_ids == {leaf_a, leaf_b}, (
        f"the refused duplicate-child request must not have created a health check; "
        f"ListHealthChecks shows {all_ids!r}, expected exactly the two leaves"
    )

    # ---- positive control: the SAME pair, but distinct, succeeds -----------------------------
    created = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "Type": "CALCULATED",
            "HealthThreshold": 0,
            "ChildHealthChecks": [leaf_a, leaf_b],
        },
    )
    calc_id = created["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_health_check(HealthCheckId=calc_id))
    created_children = set(created["HealthCheck"]["HealthCheckConfig"]["ChildHealthChecks"])
    assert created_children == {leaf_a, leaf_b}, (
        f"two distinct child IDs must both be accepted, got {created_children!r}"
    )

    # ---- read through a different operation than the one that created it --------------------
    read_back = r53.get_health_check(HealthCheckId=calc_id)
    read_children = set(read_back["HealthCheck"]["HealthCheckConfig"]["ChildHealthChecks"])
    assert read_children == {leaf_a, leaf_b}, (
        f"GetHealthCheck must read back the same two distinct children, got {read_children!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
