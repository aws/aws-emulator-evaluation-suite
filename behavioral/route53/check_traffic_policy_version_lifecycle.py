"""traffic-policy-version-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "traffic-policy-version-lifecycle"
GROUP = 'traffic-policy'
SERVICES = ['route53']


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _best_effort_delete(r53, tp_id, version):
    try:
        r53.delete_traffic_policy(Id=tp_id, Version=version)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchTrafficPolicy":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrafficPolicyVersion increments Version by 1 and both versions stay gettable.
    Deleting one version unlists it and blocks further mutation, yet GetTrafficPolicy by
    id+version still returns its document; the other version is untouched."""
    r53 = ctx.client("route53")
    doc_v1 = '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A","Endpoints":{"e1":{"Type":"value","Value":"192.0.2.1"}},"StartEndpoint":"e1"}'
    resp = r53.create_traffic_policy(Name=ctx.unique_name("sim2real-behav-tp"), Document=doc_v1, Comment="v1")
    tp_id = resp["TrafficPolicy"]["Id"]
    v1 = resp["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=tp_id, v=v1: _best_effort_delete(r53, i, v))
    assert v1 == 1, f"expected the first version to be 1, got {v1}"

    doc_v2 = '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A","Endpoints":{"e1":{"Type":"value","Value":"192.0.2.2"}},"StartEndpoint":"e1"}'
    resp2 = r53.create_traffic_policy_version(Id=tp_id, Document=doc_v2, Comment="v2")
    v2 = resp2["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=tp_id, v=v2: _best_effort_delete(r53, i, v))
    assert v2 == v1 + 1, f"expected version to increment by 1 from {v1}, got {v2}"

    got_v1 = r53.get_traffic_policy(Id=tp_id, Version=v1)
    got_v2 = r53.get_traffic_policy(Id=tp_id, Version=v2)
    assert got_v1["TrafficPolicy"]["Document"] == doc_v1, (
        f"v{v1} document diverged: {got_v1['TrafficPolicy']['Document']!r} != {doc_v1!r}"
    )
    assert got_v2["TrafficPolicy"]["Document"] == doc_v2, (
        f"v{v2} document diverged: {got_v2['TrafficPolicy']['Document']!r} != {doc_v2!r}"
    )

    versions = r53.list_traffic_policy_versions(Id=tp_id)
    seen = {v["Version"] for v in versions["TrafficPolicies"]}
    assert {v1, v2} <= seen, f"expected versions {{{v1}, {v2}}} in {seen}"

    # DeleteTrafficPolicy(v2) unlists and blocks
    # further mutation on v2 immediately, but Get by id+version still returns the same document --
    # deletion is enforced at the enumeration/mutation boundary, not at the direct-read boundary.
    r53.delete_traffic_policy(Id=tp_id, Version=v2)

    versions_after = r53.list_traffic_policy_versions(Id=tp_id)
    seen_after = {v["Version"] for v in versions_after["TrafficPolicies"]}
    assert v2 not in seen_after, f"deleted version {v2} still listed in {seen_after}"
    assert v1 in seen_after, f"surviving version {v1} vanished from {seen_after}"

    err = _client_error(lambda: r53.update_traffic_policy_comment(Id=tp_id, Version=v2, Comment="x"))
    assert err.get("Code") == "NoSuchTrafficPolicy", (
        f"expected NoSuchTrafficPolicy mutating deleted v{v2}, got {err!r}"
    )
    assert err.get("Message") == "The policy does not exist.", err

    still_readable = r53.get_traffic_policy(Id=tp_id, Version=v2)
    assert still_readable["TrafficPolicy"]["Document"] == doc_v2, (
        f"Get on a deleted version must still return its original document (real AWS does not "
        f"404 here): got {still_readable['TrafficPolicy']['Document']!r} != {doc_v2!r}"
    )

    still_there = r53.get_traffic_policy(Id=tp_id, Version=v1)
    assert still_there["TrafficPolicy"]["Document"] == doc_v1, "deleting v2 must not affect v1's document"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
