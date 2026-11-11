"""get-reputation-entity-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-reputation-entity-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReputationEntity for a well-formed but never-created tenant reference is rejected with
    BadRequestException and its exact message, while the real tenant's reputation entity reads back with its
    own reference.
    """
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    tenant = sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    tenant_arn = tenant["TenantArn"]
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))

    # A well-formed ARN in the shape of a real tenant reference that was never created, so the
    # failure is about the reference not resolving, not about a malformed ARN string.
    bogus_reference = tenant_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-nonexistent-entity")
    err = _error(
        lambda: sesv2.get_reputation_entity(
            ReputationEntityType="RESOURCE", ReputationEntityReference=bogus_reference
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err!r}"
    expected = f"ReputationEntity <{bogus_reference}> does not exist"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # positive control: the tenant's own reputation entity is readable
    entity = sesv2.get_reputation_entity(
        ReputationEntityType="RESOURCE", ReputationEntityReference=tenant_arn
    )["ReputationEntity"]
    assert entity["ReputationEntityReference"] == tenant_arn


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
