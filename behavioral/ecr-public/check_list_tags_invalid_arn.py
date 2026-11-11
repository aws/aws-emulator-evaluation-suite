"""list-tags-invalid-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-invalid-arn"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a malformed resourceArn is refused InvalidParameterException with
    the exact message, while a real repository's ARN lists an empty tag set."""
    ecr = ctx.client("ecr-public")

    repo_name = ctx.unique_name("sim2real-behav-").lower()
    repo = ecr.create_repository(repositoryName=repo_name)["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    real_arn = repo["repositoryArn"]

    # Positive control: ListTagsForResource on the real repository ARN succeeds.
    ok_tags = ecr.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert ok_tags == [], f"expected a freshly created repository to have no tags, got {ok_tags}"

    # Negative: a string that isn't an ARN at all cannot address any ecr-public resource.
    bogus_arn = "not-an-arn-at-all"
    code, code_msg = _err(lambda: ecr.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_code_msg = "Invalid parameter at 'resourceArn' failed to satisfy constraint: 'Invalid ARN'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
