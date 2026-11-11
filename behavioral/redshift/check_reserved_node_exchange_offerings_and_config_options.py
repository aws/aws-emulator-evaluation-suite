"""reserved-node-exchange-offerings-and-config-options."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-node-exchange-offerings-and-config-options"
GROUP = "data-plane"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReservedNodeExchangeOfferings rejects a malformed reserved-node id with InvalidParameterValue
    and GetReservedNodeExchangeConfigurationOptions an unresolvable cluster with ClusterNotFound,
    each with its exact message, while the offering catalog is unchanged."""
    redshift = ctx.client("redshift")

    # Positive control: the general reserved-node-offering catalog needs no owned reserved
    # node and must stay readable -- proves the reserved-node subsystem itself is reachable.
    catalog = redshift.describe_reserved_node_offerings(MaxRecords=20)
    assert "ReservedNodeOfferings" in catalog, f"missing ReservedNodeOfferings key: {catalog!r}"

    bogus_reserved_node_id = ctx.unique_name("sim2real-nonexistent-rn-")
    code_offerings, message_offerings = _error(
        lambda: redshift.get_reserved_node_exchange_offerings(ReservedNodeId=bogus_reserved_node_id)
    )
    assert code_offerings == "InvalidParameterValue", f"unexpected code: {code_offerings!r}"
    expected_offerings = (
        "The parameter ReservedNodeId is not a valid identifier. Identifiers must be valid UUID "
        "strings of the form 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' where 'x' is an ASCII "
        "character a-f or 0-9."
    )
    assert message_offerings == expected_offerings, (
        f"expected message {expected_offerings!r}, got {message_offerings!r}"
    )

    # ActionType="resize-cluster" is the source-cluster exchange path (as opposed to
    # "restore-cluster", which sources from a snapshot via SnapshotIdentifier and would
    # reject a ClusterIdentifier with InvalidParameterCombination instead).
    bogus_cluster_id = ctx.unique_name("sim2real-nonexistent-cluster-")
    code_options, message_options = _error(
        lambda: redshift.get_reserved_node_exchange_configuration_options(
            ActionType="resize-cluster", ClusterIdentifier=bogus_cluster_id
        )
    )
    assert code_options == "ClusterNotFound", f"unexpected code: {code_options!r}"
    expected_options = f"The cluster {bogus_cluster_id} was not found."
    assert message_options == expected_options, (
        f"expected message {expected_options!r}, got {message_options!r}"
    )

    # Effect absent: no configuration options / offerings are fabricated for a caller that
    # holds no reserved node -- re-run the positive control to confirm the service is still
    # healthy and the rejections above were not just "the whole API is down".
    catalog_again = redshift.describe_reserved_node_offerings(MaxRecords=20)
    assert catalog_again["ReservedNodeOfferings"] == catalog["ReservedNodeOfferings"], (
        f"catalog changed across rejected calls: before={catalog['ReservedNodeOfferings']!r} "
        f"after={catalog_again['ReservedNodeOfferings']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
