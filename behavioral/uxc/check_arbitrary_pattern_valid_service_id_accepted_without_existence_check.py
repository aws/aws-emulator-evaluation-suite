"""arbitrary-pattern-valid-service-id-accepted-without-existence-check."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arbitrary-pattern-valid-service-id-accepted-without-existence-check"
GROUP = "overly-permissive"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """UpdateAccountCustomizations with a pattern-valid but unknown service id fails with ValidationException "Invalid
    services provided" and leaves visibleServices unchanged, while visibleServices ["ec2"] is then accepted and read
    back."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    baseline = ["s3"]
    uxc.update_account_customizations(visibleServices=baseline)
    got = uxc.get_account_customizations()["visibleServices"]
    assert got == baseline, f"expected baseline={baseline!r}, got visibleServices={got!r}"

    fake_service = "totally-made-up-service-xyz"
    code, message = _error(
        lambda: uxc.update_account_customizations(visibleServices=[fake_service])
    )
    assert code == "ValidationException", f"expected code=ValidationException, got {code!r}"
    assert message == "Invalid services provided", f"unexpected message={message!r}"

    # Effect absent: the rejected call must not have changed the persisted list.
    got = uxc.get_account_customizations()["visibleServices"]
    assert got == baseline, f"expected list unchanged at {baseline!r}, got {got!r}"

    # Positive control: a real service identifier still succeeds in the same file.
    resp = uxc.update_account_customizations(visibleServices=["ec2"])
    assert resp["visibleServices"] == ["ec2"], (
        f"expected update response visibleServices=['ec2'], got {resp['visibleServices']!r}"
    )
    got = uxc.get_account_customizations()["visibleServices"]
    assert got == ["ec2"], f"expected visibleServices=['ec2'] after update, got {got!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
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
