"""register-pull-time-exclusion-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-pull-time-exclusion-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]

# Amazon ECR does not publish a numeric quota for pull-time-update exclusions per
# registry, so this check probes for the limit within a bounded number of attempts
# rather than assuming a specific value (AWS reports a limit of 100, so the budget
# is set well past it); each register/list call is a cheap control-plane op with no backing
# resource, so a larger budget costs seconds, not dollars.
_MAX_ATTEMPTS = 200


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:ecr-pull-time-exclusions",
)
def run(ctx) -> None:
    """Registering pull-time-update exclusions beyond the account limit returns
    LimitExceededException, and the exclusion count does not grow past the limit."""

    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    created: list[str] = []

    def _cleanup():
        for arn in created:
            try:
                ecr.deregister_pull_time_update_exclusion(principalArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    code = None
    message = None
    rejected_arn = None
    for i in range(_MAX_ATTEMPTS):
        role_name = ctx.unique_name(f"sim2real-ecr-lim-{i}-").replace("_", "-")
        principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        try:
            ecr.register_pull_time_update_exclusion(principalArn=principal_arn)
            created.append(principal_arn)
        except Exception as e:
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                code = e.response["Error"]["Code"]
                message = e.response["Error"].get("Message")
            rejected_arn = principal_arn
            break

    if code is None:
        raise AssertionError(
            f"could not reach the (undocumented) pull-time-update-exclusion account "
            f"limit within {_MAX_ATTEMPTS} registrations; closing this requires the "
            f"exact published quota value to bound the attempt loop precisely"
        )

    assert code == "LimitExceededException", (
        f"expected LimitExceededException once the account limit was hit, got {code!r}"
    )
    expected_message = (
        f"The registry with id '{account_id}' has the maximum number of pull time update "
        f"exclusions allowed, which is 100."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )
    # The rejected call must not have been counted: the exclusion list still only
    # contains the ones that succeeded before the limit was hit, and the rejected
    # principal itself never persisted.
    listed_arns = set(_list_all_exclusions(ecr))
    for arn in created:
        assert arn in listed_arns, (
            f"exclusion {arn} was registered before the limit was hit but is missing "
            f"from ListPullTimeUpdateExclusions"
        )
    assert rejected_arn not in listed_arns, (
        f"rejected exclusion {rejected_arn} was denied with LimitExceededException but "
        f"still appears in ListPullTimeUpdateExclusions"
    )


def _list_all_exclusions(ecr) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
