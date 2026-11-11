"""create-host-with-tags-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-host-with-tags-persisted"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateHost time are persisted and readable via ListTagsForResource."""
    csc = ctx.client("codestar-connections")
    arn = csc.create_host(
        Name=ctx.unique_name("sim2real-behav-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghes-tagged.example.com",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: csc.delete_host(HostArn=arn))

    tags = {t["Key"]: t["Value"] for t in csc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-purpose") == "behavioral-check", (
        f"expected tag sim2real-purpose=behavioral-check on {arn}, got tags={tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
