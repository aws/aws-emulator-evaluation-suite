"""servicecatalog-portfolio-status-toggle-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "servicecatalog-portfolio-status-toggle-reflected"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """Toggling the account's SageMaker ServiceCatalog portfolio association
    via Enable/Disable is immediately reflected by
    GetSagemakerServicecatalogPortfolioStatus, in both directions."""
    sm = ctx.client("sagemaker")
    original = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    ctx.on_cleanup(lambda: _restore(ctx, original))

    sm.disable_sagemaker_servicecatalog_portfolio()
    disabled_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert disabled_status == "Disabled", f"expected Disabled after disable, got {disabled_status!r}"

    sm.enable_sagemaker_servicecatalog_portfolio()
    enabled_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert enabled_status == "Enabled", f"expected Enabled after enable, got {enabled_status!r}"


def _restore(ctx, original):
    sm = ctx.client("sagemaker")
    if original == "Enabled":
        sm.enable_sagemaker_servicecatalog_portfolio()
    else:
        sm.disable_sagemaker_servicecatalog_portfolio()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
