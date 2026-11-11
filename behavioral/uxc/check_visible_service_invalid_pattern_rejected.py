"""visible-service-invalid-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visible-service-invalid-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """A visibleServices entry that breaks the ^[a-z0-9]+(-[a-z0-9]+)*$ pattern fails with BadRequestException "Invalid
    request body" and leaves the list ["s3"], while ["ec2", "lambda"] is then accepted and read back."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    uxc.update_account_customizations(visibleServices=["s3"])
    assert uxc.get_account_customizations()["visibleServices"] == ["s3"]

    code, message = _error(
        lambda: uxc.update_account_customizations(visibleServices=["Invalid_Service!"])
    )
    assert code == "BadRequestException", f"expected BadRequestException, got code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Effect absent: the invalid call must not have changed the persisted list.
    assert uxc.get_account_customizations()["visibleServices"] == ["s3"]

    # Positive control: a pattern-valid update in the same file still succeeds.
    resp = uxc.update_account_customizations(visibleServices=["ec2", "lambda"])
    assert sorted(resp["visibleServices"]) == ["ec2", "lambda"]
    assert sorted(uxc.get_account_customizations()["visibleServices"]) == ["ec2", "lambda"]


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
