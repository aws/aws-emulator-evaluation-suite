"""create-billing-view-non-management-account-deterministic-rejection."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-billing-view-non-management-account-deterministic-rejection"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-management account, five concurrent CreateBillingView calls are all rejected
    with ValidationException, never a mix of codes or a stray success that leaves a view behind:
    the call is gated on being the Organizations management account."""
    billing = ctx.client("billing")
    primary_arn = _primary_view_arn(ctx)

    def attempt(i):
        name = ctx.unique_name(f"sim2real-behav-race-{i}-")
        try:
            arn = billing.create_billing_view(name=name, sourceViews=[primary_arn])["arn"]
            ctx.on_cleanup(lambda: _safe_delete(ctx, arn))
            return ("ok", name, arn)
        except Exception as exc:  # noqa: BLE001
            error = getattr(exc, "response", {}).get("Error", {})
            return ("err", name, (error.get("Code"), error.get("Message")))

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    successes = [(name, arn) for kind, name, arn in results if kind == "ok"]
    failures = [code for kind, _name, code in results if kind == "err"]
    attempted_names = {name for _kind, name, _payload in results}

    assert len(successes) == 0, f"expected zero successes from a non-management account, got: {results}"
    assert len(failures) == 5, f"expected all 5 calls to fail, got {results}"
    assert all(code == "ValidationException" for code, _message in failures), failures
    expected_message = (
        "User account is not an AWS Organization's management account. "
        "This operation is only permitted to management accounts."
    )
    assert all(message == expected_message for _code, message in failures), failures

    # independent read, at a different operation than the mutating one: none of the
    # rejected attempts left a CUSTOM billing view behind under its attempted name.
    custom_names = {v["name"] for v in billing.list_billing_views(billingViewTypes=["CUSTOM"])["billingViews"]}
    leaked = custom_names & attempted_names
    assert not leaked, f"rejected create_billing_view calls left a view behind: {leaked}"


def _primary_view_arn(ctx):
    billing = ctx.client("billing")
    views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(views) == 1, f"expected exactly one PRIMARY billing view, got {len(views)}"
    return views[0]["arn"]


def _safe_delete(ctx, arn):
    billing = ctx.client("billing")
    try:
        billing.delete_billing_view(arn=arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
