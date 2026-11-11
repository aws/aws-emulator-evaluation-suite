"""list-tags-for-resource-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on an ARN of no resource raises ResourceNotFoundException "No connection
    exists with the ARN", while a real connection's ARN returns its owner tag."""
    cc = ctx.client("codeconnections")

    conn_name = ctx.unique_name("sim2real-conn-")[:32]
    conn_arn = cc.create_connection(
        ConnectionName=conn_name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    real_tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert real_tags == {"owner": "sim2real"}, f"positive control: expected owner tag, got {real_tags!r}"

    fake_arn = f"arn:aws:codeconnections:{ctx.region}:{ctx.account}:connection/{uuid.uuid4()}"
    code, message = _error(lambda: cc.list_tags_for_resource(ResourceArn=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "No connection exists with the ARN", f"message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
