"""servicecatalog-portfolio-status-reflects-managed-state."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "servicecatalog-portfolio-status-reflects-managed-state"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sagemaker-servicecatalog-portfolio")
def run(ctx: Any) -> None:
    """GetSagemakerServicecatalogPortfolioStatus reports a server-computed value that
    tracks the account's actual ServiceCatalog portfolio association - flipping the
    association via Enable/Disable must be reflected back, not a client-set flag."""
    sm = ctx.client("sagemaker")

    original_status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    ctx.on_cleanup(lambda: _restore_status(ctx, original_status))

    sm.enable_sagemaker_servicecatalog_portfolio()
    enabled_status = _poll_status(ctx, "Enabled")
    assert enabled_status == "Enabled", f"expected Enabled after enable, got {enabled_status!r}"

    sm.disable_sagemaker_servicecatalog_portfolio()
    disabled_status = _poll_status(ctx, "Disabled")
    assert disabled_status == "Disabled", f"expected Disabled after disable, got {disabled_status!r}"

    # Enable again and confirm the flip is observable a second time (not a one-shot
    # side effect the emulator only applies once).
    sm.enable_sagemaker_servicecatalog_portfolio()
    re_enabled_status = _poll_status(ctx, "Enabled")
    assert re_enabled_status == "Enabled", (
        f"expected Enabled after re-enabling, got {re_enabled_status!r}"
    )


def _poll_status(ctx: Any, want: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> str:
    import time

    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
    while time.monotonic() < deadline:
        status = sm.get_sagemaker_servicecatalog_portfolio_status()["Status"]
        if status == want:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"status did not reach {want!r} within {timeout_s}s (last observed {status!r})")


def _restore_status(ctx: Any, original_status: str) -> None:
    sm = ctx.client("sagemaker")
    if original_status == "Enabled":
        sm.enable_sagemaker_servicecatalog_portfolio()
    else:
        sm.disable_sagemaker_servicecatalog_portfolio()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
