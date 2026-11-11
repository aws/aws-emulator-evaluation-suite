"""get-sagemaker-servicecatalog-portfolio-status-valid-enum."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sagemaker-servicecatalog-portfolio-status-valid-enum"
GROUP = "data-plane"
SERVICES = ["sagemaker"]

_VALID_STATUSES = {"Enabled", "Disabled"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus returns a real enum value and flips when toggled."""
    sm = ctx.client("sagemaker")

    original_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert original_status in _VALID_STATUSES, f"unexpected status value: {original_status!r}"

    # Restore the account-level setting to whatever it was before this check ran, regardless of
    # outcome: it is a global (non-namespaced) account setting.
    ctx.on_cleanup(lambda: _set_status(sm, original_status))

    toggled_status = "Disabled" if original_status == "Enabled" else "Enabled"
    _set_status(sm, toggled_status)

    observed = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert observed in _VALID_STATUSES, f"unexpected status value after toggle: {observed!r}"
    assert observed == toggled_status, (
        f"status did not flip to {toggled_status!r} after Enable/DisableSagemakerServicecatalogPortfolio, "
        f"got {observed!r}"
    )
    assert observed != original_status, (
        f"status did not change from original {original_status!r} after toggling"
    )


def _set_status(sm, status):
    if status == "Enabled":
        sm.enable_sagemaker_servicecatalog_portfolio()
    else:
        sm.disable_sagemaker_servicecatalog_portfolio()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
