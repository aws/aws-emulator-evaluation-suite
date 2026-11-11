"""tag-resource-nonexistent-pool-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-pool-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource against a syntactically valid but non-existent identity pool ARN
    fails with ResourceNotFoundException rather than creating a dangling tag entry,
    while the identical call against a real pool succeeds."""
    ci = ctx.client("cognito-identity")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: TagResource/ListTagsForResource work against a real pool, so the
    # negative below cannot be mistaken for "rejects every TagResource call".
    pool_name = ctx.unique_name("sim2real_behav_tagpool_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=False
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    real_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    ci.tag_resource(ResourceArn=real_arn, Tags={"Env": "Test"})
    real_tags = ci.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert real_tags.get("Env") == "Test", real_tags

    fake_pool_id = f"{ctx.region}:{uuid.uuid4()}"
    fake_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{fake_pool_id}"

    not_found = f"IdentityPool '{fake_pool_id}' not found."
    code, message = _error(lambda: ci.tag_resource(ResourceArn=fake_arn, Tags={"Env": "Test"}))
    assert code == "ResourceNotFoundException", code
    assert message == not_found, message

    # No dangling tag entry was created: reading tags for the same fake ARN also 404s.
    list_code, list_message = _error(lambda: ci.list_tags_for_resource(ResourceArn=fake_arn))
    assert list_code == "ResourceNotFoundException", list_code
    assert list_message == not_found, list_message


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
