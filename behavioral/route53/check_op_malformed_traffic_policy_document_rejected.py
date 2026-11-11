"""op-malformed-traffic-policy-document-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "op-malformed-traffic-policy-document-rejected"
GROUP = 'traffic-policy'
SERVICES = ['route53']


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrafficPolicy with a structurally invalid document is rejected with
    InvalidTrafficPolicyDocument; the same call with a well-formed document succeeds,
    so the refusal is about the document, not a blanket rejection of the operation."""
    r53 = ctx.client("route53")
    code, message = _client_error(
        lambda: r53.create_traffic_policy(
            Name=ctx.unique_name("chk-op-badtp-"),
            Document='{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A"}',
        )
    )
    assert code == "InvalidTrafficPolicyDocument", (
        f"expected InvalidTrafficPolicyDocument for a document missing Endpoints/StartEndpoint, got {code}"
    )
    expected_message = (
        "At least one endpoint must be declared.;"
        "Either StartRule or StartEndpoint must be declared, but not both"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the same call, with a structurally complete document, succeeds
    # and the document round-trips through an independent read.
    good_doc = (
        '{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A",'
        '"Endpoints":{"e1":{"Type":"value","Value":"192.0.2.1"}},"StartEndpoint":"e1"}'
    )
    resp = r53.create_traffic_policy(Name=ctx.unique_name("chk-op-goodtp-"), Document=good_doc)
    tp_id = resp["TrafficPolicy"]["Id"]
    tp_version = resp["TrafficPolicy"]["Version"]
    ctx.on_cleanup(lambda: r53.delete_traffic_policy(Id=tp_id, Version=tp_version))

    got = r53.get_traffic_policy(Id=tp_id, Version=tp_version)
    assert got["TrafficPolicy"]["Document"] == good_doc, (
        f"expected the well-formed document to round-trip via an independent read, "
        f"got {got['TrafficPolicy']['Document']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
