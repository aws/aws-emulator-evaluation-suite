"""tag-resource-exceeds-tag-limit-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-tag-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """TagResource with more than the documented 50-tag limit is rejected (BadRequestException on real AWS), and no tags from that call are applied."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)

    too_many_tags = {f"key{i}": f"value{i}" for i in range(51)}
    code, message = _error(lambda: aiops.tag_resource(resourceArn=arn, tags=too_many_tags))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "The resultant tag set must not have more than 50 user tags."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: none of the rejected tags were applied.
    tags_after = aiops.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {}, f"expected no tags applied after the rejected TagResource, got {tags_after!r}"

    # Positive control: a small, valid tag set is accepted on the same resource.
    aiops.tag_resource(resourceArn=arn, tags={"env": "test"})
    tags_final = aiops.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_final == {"env": "test"}, f"expected {{'env': 'test'}} to persist, got {tags_final!r}"


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(name=name, roleArn=role_arn, **kwargs)
            arn = resp["arn"]
            ctx.on_cleanup(lambda a=arn: aiops.delete_investigation_group(identifier=a))
            return name, arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "ResourceNotFoundException"
                or code == "ServiceQuotaExceededException"
                or (code == "ValidationException" and "assume" in msg.lower())
            ):
                # ResourceNotFoundException: freshly created IAM role may not have propagated
                # yet. ServiceQuotaExceededException: aiops allows only one investigation
                # group per account/Region, so another concurrently running check may
                # transiently hold the singleton slot; wait for it to free up.
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
