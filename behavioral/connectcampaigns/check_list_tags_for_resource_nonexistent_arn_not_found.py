"""list-tags-for-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed campaign ARN of the caller's account and region that matches no
    campaign fails with NotFoundException "Resource was not found"."""
    cc = ctx.client("connectcampaigns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:connect-campaigns:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-fake-')}"
    )
    code, message = _error(lambda: cc.list_tags_for_resource(arn=fake_arn))
    assert code == "NotFoundException", f"{code}: {message}"
    assert message == "Resource was not found", message


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
