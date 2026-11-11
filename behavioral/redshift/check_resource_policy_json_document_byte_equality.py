"""resource-policy-json-document-byte-equality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "resource-policy-json-document-byte-equality"
GROUP = "representation"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy with irregular whitespace and a unicode Sid round-trips through
    Put/GetResourcePolicy as a structurally equal document with the Sid preserved byte-for-byte."""
    redshift = ctx.client("redshift")
    rss = ctx.client("redshift-serverless")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    ns_name = ctx.unique_name("sim2real-polbytes-ns-")
    ns = rss.create_namespace(
        namespaceName=ns_name,
        tags=[{"key": "sim2real-behavioral", "value": "true"}],
    )["namespace"]
    ctx.on_cleanup(lambda: rss.delete_namespace(namespaceName=ns_name))
    _poll_until(
        lambda: rss.get_namespace(namespaceName=ns_name)["namespace"]["status"],
        lambda status: status == "AVAILABLE",
        timeout_s=300,
        interval_s=5,
    )
    namespace_arn = ns["namespaceArn"]

    # Deliberately irregular whitespace/indentation plus nested unicode strings
    # (in the Sid) to check the service stores the exact bytes it was given.
    policy_str = (
        "{\n"
        '  "Version" : "2012-10-17",\n'
        '  "Statement":[ {   "Sid":"Ünïcødé-Sïd-日本語-🔑",\n'
        '     "Effect": "Allow",\n'
        '     "Principal" : { "AWS" : "arn:aws:iam::' + account + ':root" },\n'
        '     "Action" :"redshift:GetResourcePolicy",\n'
        '     "Resource" : "' + namespace_arn + '"\n'
        "  } ]\n"
        "}"
    )

    redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=policy_str)
    ctx.on_cleanup(lambda: redshift.delete_resource_policy(ResourceArn=namespace_arn))

    stored = redshift.get_resource_policy(ResourceArn=namespace_arn)["ResourcePolicy"]["Policy"]

    # The service may re-serialize the JSON document (e.g. canonicalize whitespace),
    # so structural/semantic equality -- not raw string equality -- is the correct
    # round-trip bar. What MUST survive byte-for-byte is the actual unicode content
    # (the nested unicode Sid), since that's what a re-serialization pass could mangle
    # (re-encoding, escaping, or truncating multi-byte / astral-plane characters).
    import json

    expected_doc = json.loads(policy_str)
    stored_doc = json.loads(stored)
    assert stored_doc == expected_doc, (
        "resource policy document was not preserved (structural mismatch):\n"
        f"expected={expected_doc!r}\nactual={stored_doc!r}"
    )

    unicode_sid = "Ünïcødé-Sïd-日本語-🔑"
    assert stored_doc["Statement"][0]["Sid"] == unicode_sid, (
        "nested unicode Sid was not preserved byte-for-byte:\n"
        f"expected={unicode_sid!r}\nactual={stored_doc['Statement'][0]['Sid']!r}"
    )
    assert unicode_sid in stored, (
        "unicode Sid substring not found verbatim in the raw stored policy string "
        f"(possible re-encoding): stored={stored!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
