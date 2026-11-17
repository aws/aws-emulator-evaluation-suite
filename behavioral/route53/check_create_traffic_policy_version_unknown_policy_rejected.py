"""create-traffic-policy-version-unknown-policy-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-traffic-policy-version-unknown-policy-rejected"
GROUP = "traffic-policy"
SERVICES = ["route53"]

_DOCUMENT_V1 = (
    '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A",'
    '"Endpoints":{"primary":{"Type":"value","Value":"192.0.2.10"}},'
    '"StartEndpoint":"primary"}'
)
_DOCUMENT_V2 = (
    '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A",'
    '"Endpoints":{"primary":{"Type":"value","Value":"192.0.2.20"}},'
    '"StartEndpoint":"primary"}'
)


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_all_versions(r53, policy_id: str, versions: list[int]) -> None:
    """Delete every listed version, tolerating a version already gone."""
    for version in versions:
        try:
            r53.delete_traffic_policy(Id=policy_id, Version=version)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchTrafficPolicy":
                raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrafficPolicyVersion on a traffic policy id that was never created answers
    NoSuchTrafficPolicy, after a positive control creates a second version on a live policy.
    """
    r53 = ctx.client("route53")
    policy_name = ctx.unique_name("sim2real-behav-tpv-")
    created = r53.create_traffic_policy(Name=policy_name, Document=_DOCUMENT_V1)
    policy_id = created["TrafficPolicy"]["Id"]
    v1 = created["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=policy_id: _delete_all_versions(r53, i, [1, 2]))
    assert v1 == 1, f"expected the first version to be 1, got {v1}"

    # Positive control: CreateTrafficPolicyVersion on the live policy succeeds.
    v2_resp = r53.create_traffic_policy_version(Id=policy_id, Document=_DOCUMENT_V2)
    v2 = v2_resp["TrafficPolicy"]["Version"]
    assert v2 == v1 + 1, f"expected version to increment by 1 from {v1}, got {v2}"

    # Break: the identical call against a traffic policy id that was never created.
    unknown_id = str(uuid.uuid4())
    err = _error(lambda: r53.create_traffic_policy_version(Id=unknown_id, Document=_DOCUMENT_V2))
    assert err.get("Code") == "NoSuchTrafficPolicy", (
        f"expected NoSuchTrafficPolicy creating a version on unknown policy {unknown_id!r}, "
        f"got {err!r}"
    )
    assert err.get("Message") == "", err

    # The refused call created no policy under the unknown id.
    listed = {t["Id"] for t in r53.list_traffic_policies()["TrafficPolicySummaries"]}
    assert unknown_id not in listed, f"{unknown_id} appeared in ListTrafficPolicies after the refusal"
    assert policy_id in listed, f"{policy_id} missing from ListTrafficPolicies"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
