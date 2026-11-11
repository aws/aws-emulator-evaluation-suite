"""tag-resource-rejects-reserved-aws-key."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-reserved-aws-key"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the
    strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _identity_pool_arn(ctx, pool_id):
    """The cognito-identity pool ARN: arn:aws:cognito-identity:<region>:<account>:identitypool/<pool-id>."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account}:identitypool/{pool_id}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a reserved `aws:`-prefixed tag key with InvalidParameterException —
    reserved keys are not silently accepted and stored as if they were ordinary customer tags —
    while an ordinary tag key on the identical resource still succeeds and persists."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    arn = _identity_pool_arn(ctx, pool_id)

    code, message = _error(
        lambda: ev.tag_resource(ResourceArn=arn, Tags={"aws:reserved-tag": "value"})
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException tagging with a reserved 'aws:' prefixed key, got {code}"
    )
    assert message == "Caller is an end user and not allowed to mutate system tags", message

    tags = ev.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:reserved-tag" not in tags, (
        f"expected the rejected reserved-prefix tag to NOT be stored, got {tags}"
    )

    # Positive control: without it, "rejects a reserved aws:-prefixed key" is indistinguishable
    # from "rejects every TagResource call" -- prove the same wiring accepts an ordinary key.
    ev.tag_resource(ResourceArn=arn, Tags={"ordinary-tag": "value"})
    tags_after = ev.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after.get("ordinary-tag") == "value", (
        f"expected an ordinary (non-reserved) tag key to be accepted and stored, got {tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
