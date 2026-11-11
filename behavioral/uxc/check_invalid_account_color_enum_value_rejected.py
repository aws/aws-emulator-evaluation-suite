"""invalid-account-color-enum-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-account-color-enum-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """An accountColor outside the enum fails with BadRequestException "Invalid request body" and leaves the color
    "red", while an update to "green" then succeeds and reads back."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    uxc.update_account_customizations(accountColor="red")
    got = uxc.get_account_customizations()["accountColor"]
    assert got == "red", f"expected accountColor='red' after the priming update, got {got!r}"

    code, message = _error(lambda: uxc.update_account_customizations(accountColor="chartreuse"))
    assert code == "BadRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Effect absent: the invalid call must not have changed the persisted color.
    got = uxc.get_account_customizations()["accountColor"]
    assert got == "red", f"expected accountColor to remain 'red' after the rejected update, got {got!r}"

    # Positive control: a valid color update in the same file still succeeds.
    resp = uxc.update_account_customizations(accountColor="green")
    assert resp["accountColor"] == "green", f"expected accountColor='green' in the update response, got {resp['accountColor']!r}"
    got = uxc.get_account_customizations()["accountColor"]
    assert got == "green", f"expected accountColor='green' after the recovery update, got {got!r}"


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
