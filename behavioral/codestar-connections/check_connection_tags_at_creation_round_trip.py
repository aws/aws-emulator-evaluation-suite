"""connection-tags-at-creation-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-tags-at-creation-round-trip"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateConnection are echoed in the response and persisted for later retrieval."""
    cc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-cn-")[:32]
    tags = [{"Key": "sim2real-env", "Value": "test"}]
    resp = cc.create_connection(ConnectionName=name, ProviderType="GitHub", Tags=tags)
    arn = resp["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, arn))

    assert resp["Tags"] == tags, f"expected CreateConnection to echo Tags {tags!r}, got {resp['Tags']!r}"

    got_tags = cc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert got_tags == tags, f"expected ListTagsForResource({arn}) to return {tags!r}, got {got_tags!r}"


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
