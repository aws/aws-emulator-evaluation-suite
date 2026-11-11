"""op-contract-getAccountSummary."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-getAccountSummary"
GROUP = "error-semantics"
SERVICES = ["iam"]

_EXPECTED_KEYS = {"Users", "UsersQuota", "Roles", "RolesQuota", "Groups", "Policies"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountSummary's SummaryMap isn't a static/fixed snapshot: creating a
    new IAM user must be reflected in the "Users" counter (polled, since the
    summary can be eventually consistent on real AWS)."""
    iam = ctx.client("iam")

    before = iam.get_account_summary()["SummaryMap"]
    missing = _EXPECTED_KEYS - before.keys()
    assert not missing, f"SummaryMap missing expected keys: {missing}"
    for key in _EXPECTED_KEYS:
        assert isinstance(before[key], int), f"{key} is not an int: {before[key]!r}"

    user_name = ctx.unique_name("sim2real-behav-summary-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": "op-contract-get-account-summary"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # Use >= rather than == : other concurrently-running checks in this shared
    # account may also be creating/deleting users, so we only require that our
    # own creation is reflected, not that we're the only mutator.
    expected_minimum = before["Users"] + 1
    final_count = before["Users"]
    # Bounded by the runner's remaining time, so a count that never converges fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        final_count = iam.get_account_summary()["SummaryMap"]["Users"]
        if final_count >= expected_minimum:
            break
        time.sleep(2.0)

    assert final_count >= expected_minimum, (
        f"Users count never reached {expected_minimum} (last seen {final_count}) "
        f"after creating {user_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
