"""list-activities-invalid-token-and-max-results-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-activities-invalid-token-and-max-results-rejected"
GROUP = "activities"
SERVICES = ["stepfunctions"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises too, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _all_activity_arns(sfn) -> set:
    """Every activity ARN over every page: the account may hold more than one page, so a
    single page is not enough to assert membership against."""
    arns: set = set()
    for page in sfn.get_paginator("list_activities").paginate():
        arns.update(a["activityArn"] for a in page["activities"])
    return arns


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListActivities rejects a corrupted nextToken and a maxResults over 1000, each with its
    exact code and message, while the same call with a valid token still succeeds.
    """
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))

    # Positive control: a plain ListActivities call succeeds and surfaces the activity.
    control_arns = _all_activity_arns(sfn)
    assert arn in control_arns, f"expected {arn!r} in ListActivities, got {len(control_arns)} activities"

    token_code, token_message = _error(lambda: sfn.list_activities(nextToken="not-a-real-token"))
    assert token_code == "InvalidToken", f"expected InvalidToken, got {token_code!r}"
    expected_token_message = "Invalid Token: 'Invalid token'"
    assert token_message == expected_token_message, (
        f"expected message {expected_token_message!r}, got {token_message!r}"
    )

    max_results_code, max_results_message = _error(lambda: sfn.list_activities(maxResults=1001))
    assert max_results_code == "ValidationException", (
        f"expected ValidationException, got {max_results_code!r}"
    )
    expected_max_results_message = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    )
    assert max_results_message == expected_max_results_message, (
        f"expected message {expected_max_results_message!r}, got {max_results_message!r}"
    )

    # The identical call with a legal maxResults still succeeds afterwards.
    again_arns = _all_activity_arns(sfn)
    assert arn in again_arns, f"expected {arn!r} after the rejected calls, got {len(again_arns)} activities"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
