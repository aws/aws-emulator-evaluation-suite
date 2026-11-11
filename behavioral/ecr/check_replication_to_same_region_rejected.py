"""replication-to-same-region-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected put_replication_configuration to be rejected but it SUCCEEDED: {result!r}"
    )

CHECK = "replication-to-same-region-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """PutReplicationConfiguration to another region is accepted, while a destination in the
    registry's own region is refused InvalidParameterException with the exact message and the
    accepted rule set stays unchanged."""
    ecr = ctx.client("ecr")
    registry_id = ecr.describe_registry()["registryId"]
    region = ctx.region
    # literal: any region other than ctx.region works as the positive control's destination.
    other_region = "us-east-2" if region != "us-east-2" else "us-east-1"

    original_rules = ecr.describe_registry().get("replicationConfiguration", {}).get("rules", [])
    ctx.on_cleanup(
        lambda: ecr.put_replication_configuration(replicationConfiguration={"rules": original_rules})
    )

    # Positive control: a valid, different-region destination is accepted and persisted.
    put = ecr.put_replication_configuration(
        replicationConfiguration={
            "rules": [{"destinations": [{"region": other_region, "registryId": registry_id}]}]
        }
    )
    assert (
        put["replicationConfiguration"]["rules"][0]["destinations"][0]["region"] == other_region
    ), put
    accepted = ecr.describe_registry()["replicationConfiguration"]["rules"]
    assert any(
        d["region"] == other_region for r in accepted for d in r["destinations"]
    ), accepted

    # Negative: the identical shape pointed at the registry's own region is rejected outright.
    code, message = _client_error(
        lambda: ecr.put_replication_configuration(
            replicationConfiguration={
                "rules": [{"destinations": [{"region": region, "registryId": registry_id}]}]
            }
        )
    )
    assert code == "InvalidParameterException", code
    assert message == (
        "Invalid parameter at 'replicationConfiguration' failed to satisfy constraint: "
        "'Replication destination cannot be the same as the source registry'"
    ), message

    rules = ecr.describe_registry()["replicationConfiguration"]["rules"]
    assert all(
        d["region"] != region for r in rules for d in r["destinations"]
    ), rules
    assert any(
        d["region"] == other_region for r in rules for d in r["destinations"]
    ), rules

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
