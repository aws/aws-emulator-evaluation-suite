"""get-account-plan-state-repeated-read-stable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-plan-state-repeated-read-stable"
GROUP = "state"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two consecutive GetAccountPlanState calls return identical responses, including optional fields, or both fail
    with ResourceNotFoundException "Missing data for account: <id>"."""
    freetier = ctx.client("freetier")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    first, first_err = _read(freetier)
    second, second_err = _read(freetier)

    assert (first_err is None) == (second_err is None), (first_err, second_err)
    if first_err is not None:
        assert first_err[0] == second_err[0] == "ResourceNotFoundException", (first_err, second_err)
        expected = f"Missing data for account: {account_id}"
        assert first_err[1] == second_err[1] == expected, (expected, first_err, second_err)
        return

    first.pop("ResponseMetadata", None)
    second.pop("ResponseMetadata", None)
    assert first == second, (first, second)


def _read(freetier):
    try:
        return freetier.get_account_plan_state(), None
    except ClientError as err:
        return None, (err.response["Error"]["Code"], err.response["Error"].get("Message"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

