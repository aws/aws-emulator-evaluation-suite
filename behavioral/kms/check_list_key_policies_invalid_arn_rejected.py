"""list-key-policies-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-key-policies-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKeyPolicies with a malformed KeyId ARN in the caller's account fails with NotFoundException and the
    exact message "Invalid arn <region>", while the same call on a real key returns ["default"]."""
    kms = ctx.client("kms")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # deliberately NOT ctx.region: the malformation under test is a same-account ARN
    # naming a region other than the one the call is made in, not a region-pinned resource.
    other_region = "eu-west-1" if ctx.region != "eu-west-1" else "us-west-2"
    malformed_arn = f"arn:aws:kms:{other_region}:{account_id}:key/00000000-0000-0000-0000-000000000000"

    code, message = _error(lambda: kms.list_key_policies(KeyId=malformed_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == f"Invalid arn {other_region}", message

    # positive control: a real key always has exactly one policy, named "default"
    key_id = _create_symmetric_key(ctx)
    resp = kms.list_key_policies(KeyId=key_id)
    assert resp["PolicyNames"] == ["default"], f"expected ['default'], got {resp['PolicyNames']!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_symmetric_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        Tags=[{"TagKey": "sim2real-check", "TagValue": "list-key-policies-invalid-arn-rejected"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    return key_id


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
