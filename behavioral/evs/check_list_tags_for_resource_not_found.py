"""list-tags-for-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on an environment ARN that does not exist (but is in the
    caller's own account/region) raises ResourceNotFoundException."""
    evs = ctx.client("evs")
    account_id = ctx.account
    fake_arn = f"arn:aws:evs:{ctx.region}:{account_id}:environment/env-0000000000"
    code, message = _error(lambda: evs.list_tags_for_resource(resourceArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"ListTagsForResource on nonexistent environment ARN {fake_arn!r} returned "
        f"{code!r}, not ResourceNotFoundException"
    )
    assert message == "Resource cannot be found.", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
