"""get-sagemaker-servicecatalog-portfolio-status-idempotent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sagemaker-servicecatalog-portfolio-status-idempotent-read"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated GetSagemakerServicecatalogPortfolioStatus calls return a stable,
    consistent Enabled/Disabled status with no side effects -- the call is a pure
    read, so back-to-back invocations must never disagree or drift."""
    sm = ctx.client("sagemaker")

    first = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert first in ("Enabled", "Disabled"), f"unexpected status value: {first}"

    for _ in range(4):
        again = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert again == first, f"status drifted across repeated reads: {first!r} -> {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
