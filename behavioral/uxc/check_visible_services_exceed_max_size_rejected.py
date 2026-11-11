"""visible-services-exceed-max-size-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visible-services-exceed-max-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """visibleServices with 501 entries (over the documented max of 500) is rejected with
    BadRequestException, leaves the prior list untouched, while a real, catalog-valid list
    within the size limit is accepted."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    baseline = ["s3"]
    uxc.update_account_customizations(visibleServices=baseline)
    assert uxc.get_account_customizations()["visibleServices"] == baseline

    # Pattern-valid but not real service identifiers, so this is unambiguously over the
    # size cap regardless of catalog-membership checking. Empirically the size-cap
    # violation surfaces as BadRequestException (distinct from the ValidationException
    # used for catalog-membership violations elsewhere in this API).
    too_many = [f"svc-{i}" for i in range(501)]
    code, message = _error_code(lambda: uxc.update_account_customizations(visibleServices=too_many))
    assert code == "BadRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Effect absent: the oversized list must not have been persisted.
    assert uxc.get_account_customizations()["visibleServices"] == baseline

    # Positive control: a real, catalog-valid, well-within-limit list is accepted in the
    # same file (proves the rejection above is about the request, not a stuck/broken API).
    real_services = _collect_real_services(uxc, minimum=5)
    resp = uxc.update_account_customizations(visibleServices=real_services)
    assert sorted(resp["visibleServices"]) == sorted(real_services)
    assert sorted(uxc.get_account_customizations()["visibleServices"]) == sorted(real_services)


def _collect_real_services(uxc, minimum: int) -> list[str]:
    services: list[str] = []
    next_token = None
    while len(services) < minimum:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = uxc.list_services(**kwargs)
        services.extend(page.get("services", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert len(services) >= minimum, (
        f"real service catalog only has {len(services)} entries; need at least {minimum}"
    )
    return services[:minimum]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _snapshot(uxc):
    resp = uxc.get_account_customizations()
    return {
        "accountColor": resp.get("accountColor", "none"),
        "visibleServices": resp.get("visibleServices"),
        "visibleRegions": resp.get("visibleRegions"),
    }


def _restore(uxc, snap):
    kwargs = {"accountColor": snap["accountColor"] or "none"}
    if snap["visibleServices"] is not None:
        kwargs["visibleServices"] = snap["visibleServices"]
    if snap["visibleRegions"] is not None:
        kwargs["visibleRegions"] = snap["visibleRegions"]
    uxc.update_account_customizations(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
