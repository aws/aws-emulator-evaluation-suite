"""tag-resource-rejects-aws-prefixed-tag-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-aws-prefixed-tag-key"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_SYSTEM_TAG = ("InvalidParameterException", "Caller is an end user and not allowed to mutate system tags")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource refuses a tag key in the aws: namespace with its exact code and
    message and does not add it; an ordinary key on the same call succeeds."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    code, message = _error(lambda: idp.tag_resource(ResourceArn=pool_arn, Tags={"aws:sim2real": "x"}))
    assert (code, message) == _SYSTEM_TAG, f"expected {_SYSTEM_TAG}, got {(code, message)!r}"

    after_reject = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert "aws:sim2real" not in after_reject, (
        f"expected the rejected aws:sim2real tag to be absent, got {after_reject}"
    )

    # positive control: an ordinary key on the identical call succeeds, proving the
    # rejection above is specific to the aws: namespace and not a blanket refusal.
    idp.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-owner": "tag-resource-check"})
    after_accept = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert after_accept.get("sim2real-owner") == "tag-resource-check", (
        f"expected sim2real-owner=tag-resource-check, got {after_accept.get('sim2real-owner')!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
