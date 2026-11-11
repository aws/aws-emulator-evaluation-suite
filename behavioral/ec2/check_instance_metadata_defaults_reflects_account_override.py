"""instance-metadata-defaults-reflects-account-override."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "instance-metadata-defaults-reflects-account-override"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """GetInstanceMetadataDefaults returns the account-level overrides exactly as last modified."""
    ec2 = ctx.client("ec2")

    original = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "instance metadata defaults are managed by a declarative policy in this account "
            "and cannot be modified directly by ModifyInstanceMetadataDefaults"
        )

    original_http_tokens = original.get("HttpTokens", "no-preference")
    original_hop_limit = original.get("HttpPutResponseHopLimit") or -1
    original_http_endpoint = original.get("HttpEndpoint", "no-preference")
    original_metadata_tags = original.get("InstanceMetadataTags", "no-preference")
    original_tokens_enforced = original.get("HttpTokensEnforced", "no-preference")

    def _restore():
        ec2.modify_instance_metadata_defaults(
            HttpTokens=original_http_tokens,
            HttpPutResponseHopLimit=original_hop_limit,
            HttpEndpoint=original_http_endpoint,
            InstanceMetadataTags=original_metadata_tags,
            HttpTokensEnforced=original_tokens_enforced,
        )

    ctx.on_cleanup(_restore)

    ec2.modify_instance_metadata_defaults(
        HttpTokens="required",
        HttpPutResponseHopLimit=3,
        HttpEndpoint="enabled",
        InstanceMetadataTags="enabled",
        HttpTokensEnforced="enabled",
    )

    current = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert current["HttpTokens"] == "required", current
    assert current["HttpPutResponseHopLimit"] == 3, current
    assert current["HttpEndpoint"] == "enabled", current
    assert current["InstanceMetadataTags"] == "enabled", current
    assert current["HttpTokensEnforced"] == "enabled", current


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
