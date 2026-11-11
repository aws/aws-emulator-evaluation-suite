"""cross-account-async-invoke-access-denied."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cross-account-async-invoke-access-denied"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAsyncInvoke on a well-formed invocationArn of a foreign account is refused with
    AccessDeniedException ('The provided resource ARN is from a different account.'), the ARN is
    absent from ListAsyncInvokes, and ListAsyncInvokes succeeds.
    """
    bedrock = ctx.client("bedrock-runtime")
    sts = ctx.client("sts")
    own_account_id = sts.get_caller_identity()["Account"]

    # A syntactically valid but different 12-digit account id, guaranteed not to be ours.
    foreign_account_id = "".join("9" if d == "0" else "0" for d in own_account_id.rjust(12, "0"))
    assert foreign_account_id != own_account_id
    foreign_arn = f"arn:aws:bedrock:{ctx.region}:{foreign_account_id}:async-invoke/abcdef123456"

    code, message = _error_code(lambda: bedrock.get_async_invoke(invocationArn=foreign_arn))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a foreign account's invocationArn, got {code!r}"
    )
    assert message == "The provided resource ARN is from a different account.", message

    # effect absent: the foreign arn never shows up in our own account's listing.
    listed_arns = {
        s["invocationArn"]
        for s in bedrock.list_async_invokes(maxResults=100).get("asyncInvokeSummaries", [])
    }
    assert foreign_arn not in listed_arns

    # positive control: the same client/credentials still succeed against a sibling read call.
    control = bedrock.list_async_invokes(maxResults=1)
    assert "asyncInvokeSummaries" in control


def _error_code(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
