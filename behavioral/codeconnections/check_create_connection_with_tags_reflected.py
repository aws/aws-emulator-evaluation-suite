"""create-connection-with-tags-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-connection-with-tags-reflected"
GROUP = "tags"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateConnection are returned in the CreateConnection response and
    are independently retrievable via ListTagsForResource."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    resp = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )
    arn = resp["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    created_tags = {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
    assert created_tags == {"owner": "sim2real"}, (
        f"expected CreateConnection response Tags={{'owner': 'sim2real'}}, got {created_tags!r}"
    )

    listed_tags = {
        t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    }
    assert listed_tags == {"owner": "sim2real"}, (
        f"expected ListTagsForResource Tags={{'owner': 'sim2real'}}, got {listed_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
