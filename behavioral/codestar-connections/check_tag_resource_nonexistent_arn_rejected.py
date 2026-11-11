"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an ARN that does not correspond to an existing connection/host/
    repository-link is rejected; tagging a real connection still succeeds.
    """
    cc = ctx.client("codestar-connections")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:codestar-connections:{ctx.region}:{account}:"
        "connection/00000000-0000-0000-0000-000000000000"
    )

    err = _error(
        lambda: cc.tag_resource(ResourceArn=fake_arn, Tags=[{"Key": "sim2real-k", "Value": "v"}])
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent-in-account resource ARN, got {err!r}"
    )
    assert err["Message"] == "No connection exists with the ARN", err["Message"]

    # positive control: tagging a real connection succeeds
    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32], ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "sim2real-k", "Value": "v"}])
    tags = cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v"} in tags, (
        f"tag not applied to real connection {conn_arn!r}: {tags!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
