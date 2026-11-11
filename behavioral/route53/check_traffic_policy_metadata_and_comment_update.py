"""traffic-policy-metadata-and-comment-update."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "traffic-policy-metadata-and-comment-update"
GROUP = 'traffic-policy'
SERVICES = ['route53']

_SIMPLE_TP_DOCUMENT = (
    '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A",'
    '"Endpoints":{"endpoint-1":{"Type":"value","Value":"192.0.2.100"}},'
    '"StartEndpoint":"endpoint-1"}'
)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTrafficPolicy returns the stored document; ListTrafficPolicies includes it; UpdateTrafficPolicyComment mutates only the comment."""
    r53 = ctx.client("route53")
    tp_name = ctx.unique_name("chk-tpmeta-")
    created = r53.create_traffic_policy(Name=tp_name, Document=_SIMPLE_TP_DOCUMENT)
    policy_id = created["TrafficPolicy"]["Id"]
    version = created["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda i=policy_id, v=version: r53.delete_traffic_policy(Id=i, Version=v))

    got = r53.get_traffic_policy(Id=policy_id, Version=version)["TrafficPolicy"]
    assert got["Name"] == tp_name, got["Name"]
    assert got["Type"] == "A", got["Type"]
    assert '"StartEndpoint":"endpoint-1"' in got["Document"].replace(" ", ""), got["Document"]

    listed = {t["Id"] for t in r53.list_traffic_policies()["TrafficPolicySummaries"]}
    assert policy_id in listed, f"{policy_id} missing from ListTrafficPolicies"

    comment = "sim2real behavioral tp comment"
    updated = r53.update_traffic_policy_comment(Id=policy_id, Version=version, Comment=comment)
    assert updated["TrafficPolicy"]["Comment"] == comment, updated["TrafficPolicy"]
    reread = r53.get_traffic_policy(Id=policy_id, Version=version)["TrafficPolicy"]
    assert reread["Comment"] == comment, reread
    assert reread["Document"] == got["Document"], "comment update must not alter the document"

    # a version that was never created must be a clean not-found
    err = _client_error(lambda: r53.get_traffic_policy(Id=policy_id, Version=version + 99))
    assert err.get("Code") == "NoSuchTrafficPolicy", f"expected NoSuchTrafficPolicy, got {err!r}"
    assert err.get("Message") == "The policy does not exist.", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
