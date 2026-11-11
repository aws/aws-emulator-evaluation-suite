"""update-host-provider-endpoint-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-host-provider-endpoint-persisted"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHost changing ProviderEndpoint is durably persisted on the host."""
    csc = ctx.client("codestar-connections")
    arn = csc.create_host(
        Name=ctx.unique_name("sim2real-behav-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghes-old.example.com",
    )["HostArn"]
    ctx.on_cleanup(lambda: csc.delete_host(HostArn=arn))

    before = csc.get_host(HostArn=arn)["ProviderEndpoint"]
    assert before == "https://ghes-old.example.com", (
        f"expected ProviderEndpoint https://ghes-old.example.com at creation, got {before!r}"
    )

    csc.update_host(HostArn=arn, ProviderEndpoint="https://ghes-new.example.com")

    updated = csc.get_host(HostArn=arn)["ProviderEndpoint"]
    assert updated == "https://ghes-new.example.com", (
        f"expected ProviderEndpoint https://ghes-new.example.com after UpdateHost, got {updated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
