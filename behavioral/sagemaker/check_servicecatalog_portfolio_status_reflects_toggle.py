"""servicecatalog-portfolio-status-reflects-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "servicecatalog-portfolio-status-reflects-toggle"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus reflects the enabled/disabled state
    actually toggled via Enable/DisableSagemakerServicecatalogPortfolio, in both
    directions, rather than returning a fixed stub value."""
    sm = ctx.client("sagemaker")

    original_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    ctx.on_cleanup(lambda: _restore(sm, original_status))

    if original_status == "Enabled":
        sm.disable_sagemaker_servicecatalog_portfolio()
        after_disable = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert after_disable == "Disabled", (
            f"expected Disabled after DisableSagemakerServicecatalogPortfolio, got {after_disable!r}"
        )
        sm.enable_sagemaker_servicecatalog_portfolio()
        after_enable = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert after_enable == "Enabled", (
            f"expected Enabled after EnableSagemakerServicecatalogPortfolio, got {after_enable!r}"
        )
    else:
        sm.enable_sagemaker_servicecatalog_portfolio()
        after_enable = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert after_enable == "Enabled", (
            f"expected Enabled after EnableSagemakerServicecatalogPortfolio, got {after_enable!r}"
        )
        sm.disable_sagemaker_servicecatalog_portfolio()
        after_disable = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert after_disable == "Disabled", (
            f"expected Disabled after DisableSagemakerServicecatalogPortfolio, got {after_disable!r}"
        )


def _restore(sm, original_status: str) -> None:
    current = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    if current == original_status:
        return
    if original_status == "Enabled":
        sm.enable_sagemaker_servicecatalog_portfolio()
    else:
        sm.disable_sagemaker_servicecatalog_portfolio()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
