"""servicecatalog-portfolio-status-reflects-enablement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "servicecatalog-portfolio-status-reflects-enablement"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus reports Enabled after EnableSagemakerServicecatalogPortfolio and
    Disabled after DisableSagemakerServicecatalogPortfolio, so the status follows the setting.
    """
    sagemaker = ctx.client("sagemaker")

    original_status = sagemaker.get_sagemaker_servicecatalog_portfolio_status()["Status"]

    def _restore():
        if original_status == "Enabled":
            sagemaker.enable_sagemaker_servicecatalog_portfolio()
        else:
            sagemaker.disable_sagemaker_servicecatalog_portfolio()

    ctx.on_cleanup(_restore)

    sagemaker.enable_sagemaker_servicecatalog_portfolio()
    enabled_status = _poll_until(
        lambda: sagemaker.get_sagemaker_servicecatalog_portfolio_status()["Status"],
        lambda status: status == "Enabled",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert enabled_status == "Enabled", (
        f"expected Enabled after EnableSagemakerServicecatalogPortfolio, got {enabled_status!r}"
    )

    sagemaker.disable_sagemaker_servicecatalog_portfolio()
    disabled_status = _poll_until(
        lambda: sagemaker.get_sagemaker_servicecatalog_portfolio_status()["Status"],
        lambda status: status == "Disabled",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert disabled_status == "Disabled", (
        f"expected Disabled after DisableSagemakerServicecatalogPortfolio, got {disabled_status!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
