"""oidc-provider-tags-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "oidc-provider-tags-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging an OIDC provider makes tags visible via ListOpenIDConnectProviderTags;
    untagging removes them."""
    iam = ctx.client("iam")
    host = ctx.unique_name("sim2real-oidc-")
    url = f"https://{host}.example.com/"
    # Explicit ThumbprintList avoids IAM needing to reach the (non-existent) IdP.
    created = iam.create_open_id_connect_provider(
        Url=url,
        ClientIDList=["sts.amazonaws.com"],
        ThumbprintList=["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"],
    )
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    initial = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]
    assert initial == [], f"expected no tags before TagOpenIDConnectProvider, got {initial}"

    tag_list = [{"Key": "env", "Value": "test"}, {"Key": "federation", "Value": "web-identity"}]
    iam.tag_open_id_connect_provider(OpenIDConnectProviderArn=arn, Tags=tag_list)

    listed = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in tag_list}, (
        f"expected tags {tag_list}, got {listed}"
    )

    # Untag only "env" so the terminal read must distinguish a targeted removal from a
    # clear-all: "federation" surviving is proof UntagOpenIDConnectProvider is selective.
    iam.untag_open_id_connect_provider(OpenIDConnectProviderArn=arn, TagKeys=["env"])
    after = {t["Key"]: t["Value"] for t in iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]}
    assert "env" not in after, f"expected 'env' removed after UntagOpenIDConnectProvider, got {after}"
    assert after.get("federation") == "web-identity", (
        f"expected untouched key 'federation' to survive selective untag, got {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
