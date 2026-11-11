"""visible-services-max-length-service-id-boundary-accepted."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visible-services-max-length-service-id-boundary-accepted"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """A visibleServices entry over 64 characters, sent without client-side validation, fails with BadRequestException
    "Invalid request body" and leaves the list unchanged, while a real service id is accepted and read back."""
    uxc = ctx.client("uxc")
    raw = ctx.client("uxc", config=Config(parameter_validation=False))
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    baseline = ["s3"]
    uxc.update_account_customizations(visibleServices=baseline)
    assert uxc.get_account_customizations()["visibleServices"] == baseline

    too_long = "a" * 65
    code, message = _error(lambda: raw.update_account_customizations(visibleServices=[too_long]))
    assert code == "BadRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Effect absent: the rejected call must not have changed the persisted list.
    assert uxc.get_account_customizations()["visibleServices"] == baseline

    # Positive control: a real, well-within-the-limit service identifier still succeeds.
    real_service = "ec2"
    resp = uxc.update_account_customizations(visibleServices=[real_service])
    assert resp["visibleServices"] == [real_service]

    got = uxc.get_account_customizations()
    assert got["visibleServices"] == [real_service]


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
