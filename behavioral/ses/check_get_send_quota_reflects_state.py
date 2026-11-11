"""get-send-quota-reflects-state."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-send-quota-reflects-state"
GROUP = 'sending'
SERVICES = ['ses']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSendQuota reports Max24HourSend/MaxSendRate as positive numbers with SentLast24Hours <=
    Max24HourSend; the v2 GetAccount surface reports the identical quota grant for the same
    account, and repeated reads neither perturb the grant nor let the 24-hour counter regress."""
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    quota = v1.get_send_quota()
    assert quota["Max24HourSend"] > 0 or quota["Max24HourSend"] == -1, (
        f"unexpected Max24HourSend: {quota['Max24HourSend']}"
    )
    assert quota["MaxSendRate"] > 0, f"expected positive MaxSendRate, got {quota['MaxSendRate']}"
    if quota["Max24HourSend"] != -1:
        assert quota["SentLast24Hours"] <= quota["Max24HourSend"], (
            "SentLast24Hours exceeds the account's Max24HourSend quota"
        )

    # Independent surface, same account: sesv2 GetAccount's SendQuota is a different operation on a
    # different API version, so a target that hardcodes the two surfaces separately diverges here.
    v2_quota = v2.get_account()["SendQuota"]
    assert v2_quota["Max24HourSend"] == quota["Max24HourSend"], (
        f"v1 GetSendQuota and v2 GetAccount disagree on Max24HourSend: "
        f"{quota['Max24HourSend']} vs {v2_quota['Max24HourSend']}"
    )
    assert v2_quota["MaxSendRate"] == quota["MaxSendRate"], (
        f"v1 GetSendQuota and v2 GetAccount disagree on MaxSendRate: "
        f"{quota['MaxSendRate']} vs {v2_quota['MaxSendRate']}"
    )

    # Freeze detector: three more read-only calls, no send in between. The grant must not move and
    # the 24-hour counter must not regress -- a read must never advance or rewind account state.
    prev_sent = quota["SentLast24Hours"]
    for i in range(3):
        again = v1.get_send_quota()
        assert again["Max24HourSend"] == quota["Max24HourSend"], (
            f"Max24HourSend changed across read-only calls with no intervening mutation: "
            f"{quota['Max24HourSend']} -> {again['Max24HourSend']} (read {i})"
        )
        assert again["MaxSendRate"] == quota["MaxSendRate"], (
            f"MaxSendRate changed across read-only calls with no intervening mutation: "
            f"{quota['MaxSendRate']} -> {again['MaxSendRate']} (read {i})"
        )
        assert again["SentLast24Hours"] >= prev_sent, (
            f"SentLast24Hours regressed across read-only GetSendQuota calls: "
            f"{prev_sent} -> {again['SentLast24Hours']} (read {i})"
        )
        prev_sent = again["SentLast24Hours"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
