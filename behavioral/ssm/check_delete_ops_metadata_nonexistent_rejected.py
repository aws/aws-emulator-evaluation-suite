"""delete-ops-metadata-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-ops-metadata-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_NOT_FOUND = "OpsMetadata object not found. Verify the Amazon Resource Name (ARN) and try again."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOpsMetadata on a well-formed OpsMetadata ARN with no backing object fails with
    OpsMetadataNotFoundException instead of a silent no-op, and nothing is created.
    """
    ssm = ctx.client("ssm")

    # CreateOpsMetadata is refused (Application Manager no longer accepts new onboarding), so the
    # check targets a well-formed ARN that was never created.
    resource_id = ctx.unique_name("sim2real-opsmeta-del-")
    region = ssm.meta.region_name
    account_id = ctx.account_id() if hasattr(ctx, "account_id") else _account_id(ctx)
    arn = f"arn:aws:ssm:{region}:{account_id}:opsmetadata/aws/ssm/{resource_id}/appmanager"

    # Positive control: the OpsMetadata read/list surface works normally and confirms nothing
    # is registered under this never-created ARN.
    before = [m["ResourceId"] for m in _all_ops_metadata(ssm)]
    assert resource_id not in before, f"{resource_id} unexpectedly already listed: {before}"
    get_code, get_message = _error(lambda: ssm.get_ops_metadata(OpsMetadataArn=arn))
    assert get_code == "OpsMetadataNotFoundException", f"unexpected code: {get_code}"
    assert get_message == _NOT_FOUND, f"GetOpsMetadata message: {get_message!r}"

    # Negative: deleting a well-formed ARN with no attached OpsMetadata object must be rejected,
    # not a no-op.
    code, message = _error(lambda: ssm.delete_ops_metadata(OpsMetadataArn=arn))
    assert code == "OpsMetadataNotFoundException", f"unexpected code: {code}"
    assert message == _NOT_FOUND, f"DeleteOpsMetadata message: {message!r}"

    # Effect absent: still nothing materialized as a side effect of the rejected delete.
    still_gone_code, still_gone_message = _error(lambda: ssm.get_ops_metadata(OpsMetadataArn=arn))
    assert still_gone_code == "OpsMetadataNotFoundException", f"unexpected code: {still_gone_code}"
    assert still_gone_message == _NOT_FOUND, f"GetOpsMetadata message: {still_gone_message!r}"
    after = [m["ResourceId"] for m in _all_ops_metadata(ssm)]
    assert resource_id not in after, f"{resource_id} materialized after rejected delete: {after}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _all_ops_metadata(ssm) -> list:
    out: list = []
    kwargs: dict = {}
    while True:
        resp = ssm.list_ops_metadata(**kwargs)
        out.extend(resp.get("OpsMetadataList", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return out


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
