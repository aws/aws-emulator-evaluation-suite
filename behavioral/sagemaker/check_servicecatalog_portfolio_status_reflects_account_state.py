"""servicecatalog-portfolio-status-reflects-account-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "servicecatalog-portfolio-status-reflects-account-state"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx) -> None:
    """GetSagemakerServicecatalogPortfolioStatus reports the account's actual
    enabled/disabled state: toggling it via Enable/DisableSagemakerServicecatalogPortfolio
    changes the reported Status, rather than the call always returning a fixed default."""
    sm = ctx.client("sagemaker")

    initial_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    assert initial_status in ("Enabled", "Disabled"), (
        f"unexpected Status {initial_status!r} from GetSagemakerServicecatalogPortfolioStatus"
    )

    if initial_status == "Enabled":
        sm.disable_sagemaker_servicecatalog_portfolio()
        expected_after = "Disabled"
        restore = sm.enable_sagemaker_servicecatalog_portfolio
    else:
        sm.enable_sagemaker_servicecatalog_portfolio()
        expected_after = "Enabled"
        restore = sm.disable_sagemaker_servicecatalog_portfolio

    ctx.on_cleanup(restore)

    observed = _poll_until(
        lambda: sm.get_sagemaker_servicecatalog_portfolio_status()["Status"],
        lambda status: status == expected_after,
        timeout_s=30.0,
    )
    assert observed == expected_after, (
        f"toggled portfolio status but GetSagemakerServicecatalogPortfolioStatus still "
        f"reports {observed!r} (expected {expected_after!r}); status looks hardcoded"
    )

    # Freeze detector: two more independent reads must keep agreeing, ruling out a
    # one-shot flip that reverts or flaps rather than a durably applied state change.
    for _ in range(2):
        again = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        assert again == expected_after, (
            f"GetSagemakerServicecatalogPortfolioStatus flapped to {again!r} moments "
            f"after reporting {expected_after!r}"
        )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
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
