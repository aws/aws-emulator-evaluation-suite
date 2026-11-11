"""get-sagemaker-servicecatalog-portfolio-status-reflects-enablement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-sagemaker-servicecatalog-portfolio-status-reflects-enablement"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus reflects the server-managed enablement state
    (flipped via Enable/DisableSagemakerServicecatalogPortfolio) rather than returning a
    static default regardless of what was last set.
    """
    sm = ctx.client("sagemaker")

    original_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]

    def _restore():
        if original_status == "Enabled":
            sm.enable_sagemaker_servicecatalog_portfolio()
        else:
            sm.disable_sagemaker_servicecatalog_portfolio()

    ctx.on_cleanup(_restore)

    # Drive it to Disabled, then confirm the getter reflects that.
    sm.disable_sagemaker_servicecatalog_portfolio()
    disabled_status = _poll_until(
        lambda: sm.get_sagemaker_servicecatalog_portfolio_status()["Status"], "Disabled", timeout_s=30
    )
    assert disabled_status == "Disabled", (
        f"expected Status=='Disabled' after DisableSagemakerServicecatalogPortfolio, got {disabled_status!r}"
    )

    # Drive it to Enabled, and confirm the getter flips too -- proving it's a live read of
    # server state, not a value fixed at some earlier point.
    sm.enable_sagemaker_servicecatalog_portfolio()
    enabled_status = _poll_until(
        lambda: sm.get_sagemaker_servicecatalog_portfolio_status()["Status"], "Enabled", timeout_s=30
    )
    assert enabled_status == "Enabled", (
        f"expected Status=='Enabled' after EnableSagemakerServicecatalogPortfolio, got {enabled_status!r}"
    )


def _poll_until(probe, want: str, *, timeout_s: float, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if value == want:
            return value
        time.sleep(interval_s)
    raise AssertionError(f"status did not reach {want!r} within {timeout_s}s (last observed: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
