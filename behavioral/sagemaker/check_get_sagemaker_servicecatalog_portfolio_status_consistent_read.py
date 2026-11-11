"""get-sagemaker-servicecatalog-portfolio-status-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sagemaker-servicecatalog-portfolio-status-consistent-read"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus returns a stable Enabled/Disabled value
    across repeated reads with no intervening mutation."""
    sm = ctx.client("sagemaker")

    first = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert first in ("Enabled", "Disabled"), f"unexpected status value: {first!r}"

    for _ in range(3):
        again = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert again == first, f"status flapped between reads: {first!r} -> {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
