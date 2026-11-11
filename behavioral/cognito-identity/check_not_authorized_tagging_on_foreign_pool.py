"""not-authorized-tagging-on-foreign-pool."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-authorized-tagging-on-foreign-pool"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an over-permissive target accepting a call real AWS rejects is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")

def _identity_pool_arn(ctx, pool_id):
    """The cognito-identity pool ARN: arn:aws:cognito-identity:<region>:<account>:identitypool/<pool-id>."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account}:identitypool/{pool_id}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource, TagResource and UntagResource on the ARN of a nonexistent identity pool
    each answer ResourceNotFoundException with the exact message, while the same three calls work on
    a real pool."""
    ev = ctx.client("cognito-identity")

    # Positive control: the same three operations succeed on a real, owned pool.
    real_pool_id = ev.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=real_pool_id))
    real_arn = _identity_pool_arn(ctx, real_pool_id)

    ev.tag_resource(ResourceArn=real_arn, Tags={"k": "v"})
    control_tags = ev.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert control_tags.get("k") == "v", (
        f"positive control: expected tag k=v on a real pool, got {control_tags}"
    )
    ev.untag_resource(ResourceArn=real_arn, TagKeys=["k"])
    control_tags = ev.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert "k" not in control_tags, (
        f"positive control: expected UntagResource to remove k on a real pool, still saw {control_tags}"
    )

    # Negative: the identical three calls against a pool id that never existed.
    foreign_pool_id = f"{ctx.region}:{uuid.uuid4()}"
    arn = _identity_pool_arn(ctx, foreign_pool_id)
    expected_message = f"IdentityPool '{foreign_pool_id}' not found."

    code, message = _error(lambda: ev.list_tags_for_resource(ResourceArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for ListTagsForResource on a nonexistent pool ARN, got {code}"
    )
    assert message == expected_message, (
        f"ListTagsForResource: expected message {expected_message!r}, got {message!r}"
    )

    code, message = _error(lambda: ev.tag_resource(ResourceArn=arn, Tags={"k": "v"}))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for TagResource on a nonexistent pool ARN, got {code}"
    )
    assert message == expected_message, (
        f"TagResource: expected message {expected_message!r}, got {message!r}"
    )

    code, message = _error(lambda: ev.untag_resource(ResourceArn=arn, TagKeys=["k"]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for UntagResource on a nonexistent pool ARN, got {code}"
    )
    assert message == expected_message, (
        f"UntagResource: expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
