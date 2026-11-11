"""get-recommendations-cross-account-campaign-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-recommendations-cross-account-campaign-arn-not-found"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecommendations on a campaignArn in another account gets AccessDeniedException with its exact
    message, while the same name in the caller's account gets InvalidInputException "<arn> does not
    exist or is not active yet." instead."""
    rt = ctx.client("personalize-runtime")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    real_account = identity["Account"]
    fake_account = "123456789012" if real_account != "123456789012" else "210987654321"
    name = ctx.unique_name("sim2real-personalize-camp-")
    user_id = ctx.unique_name("user-")

    cross_account_arn = f"arn:aws:personalize:{ctx.region}:{fake_account}:campaign/{name}"
    own_account_arn = f"arn:aws:personalize:{ctx.region}:{real_account}:campaign/{name}"

    err_cross = _error(lambda: rt.get_recommendations(campaignArn=cross_account_arn, userId=user_id))
    assert err_cross["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {err_cross!r}"
    assert err_cross["Message"] == f"User: {identity['Arn']} is not authorized to access this resource", (
        f"unexpected AccessDeniedException message {err_cross['Message']!r}"
    )

    # positive control: the identical, well-formed request against our own account (also
    # nonexistent) reaches business logic instead of being denied at the authz layer.
    err_own = _error(lambda: rt.get_recommendations(campaignArn=own_account_arn, userId=user_id))
    assert err_own["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err_own!r}"
    assert err_own["Message"] == f"{own_account_arn} does not exist or is not active yet.", (
        f"unexpected InvalidInputException message {err_own['Message']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict ({"Code", "Message", ...}). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
