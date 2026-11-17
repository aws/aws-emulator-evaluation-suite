"""put-replication-configuration-invalid-repository-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "put-replication-configuration-invalid-repository-filter-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """PutReplicationConfiguration with an uppercase character in a repository filter is
    rejected with InvalidParameterException and the accepted rule set stays unchanged; the
    same destination with a lowercase filter is accepted."""
    ecr = ctx.client("ecr")
    registry_id = ecr.describe_registry()["registryId"]
    region = ctx.region
    other_region = "us-east-2" if region != "us-east-2" else "us-east-1"
    good_filter = ctx.unique_name("sim2real-behav-ecr-repl-")

    original_rules = ecr.describe_registry().get("replicationConfiguration", {}).get("rules", [])
    ctx.on_cleanup(
        lambda: ecr.put_replication_configuration(replicationConfiguration={"rules": original_rules})
    )

    put = ecr.put_replication_configuration(
        replicationConfiguration={
            "rules": [
                {
                    "destinations": [{"region": other_region, "registryId": registry_id}],
                    "repositoryFilters": [{"filter": good_filter, "filterType": "PREFIX_MATCH"}],
                }
            ]
        }
    )
    assert put["replicationConfiguration"]["rules"][0]["repositoryFilters"][0]["filter"] == (
        good_filter
    ), put

    bad_filter = good_filter + "-INVALID"
    expected = (
        "Invalid parameter at 'replicationConfiguration.rules.1.member.repositoryFilters.1."
        "member.filter' failed to satisfy constraint: 'Member must satisfy regular expression "
        "pattern: ^(?=.{1,256}$)(?:[a-z0-9*]+(?:[._-][a-z0-9*]*)*/)*[a-z0-9*]*(?:[._-]"
        "[a-z0-9*]*)*$'"
    )
    code, message = _error(
        lambda: ecr.put_replication_configuration(
            replicationConfiguration={
                "rules": [
                    {
                        "destinations": [{"region": other_region, "registryId": registry_id}],
                        "repositoryFilters": [
                            {"filter": bad_filter, "filterType": "PREFIX_MATCH"}
                        ],
                    }
                ]
            }
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    rules = ecr.describe_registry()["replicationConfiguration"]["rules"]
    filters = [f["filter"] for r in rules for f in r.get("repositoryFilters", [])]
    assert bad_filter not in filters, filters
    assert good_filter in filters, filters


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
