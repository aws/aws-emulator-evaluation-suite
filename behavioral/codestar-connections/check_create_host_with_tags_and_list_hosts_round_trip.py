"""create-host-with-tags-and-list-hosts-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-host-with-tags-and-list-hosts-round-trip"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A host created with Tags is discoverable via ListHosts and its tags via ListTagsForResource."""
    cc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-host-")
    tag = {"Key": "sim2real-purpose", "Value": "behavioral-check"}
    resp = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
        Tags=[tag],
    )
    arn = resp["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, arn))

    hosts = cc.list_hosts()["Hosts"]
    matching = [h for h in hosts if h["HostArn"] == arn]
    assert len(matching) == 1, f"expected exactly one host for {arn}, got {matching}"
    assert matching[0]["Name"] == name, (
        f"expected Name {name!r}, got {matching[0]['Name']!r}"
    )
    assert matching[0]["Status"] == "PENDING", (
        f"expected Status PENDING, got {matching[0]['Status']!r}"
    )

    got_tags = cc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tag in got_tags, f"expected tag {tag!r} in {got_tags}"


def _safe_delete_host(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_host(HostArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
