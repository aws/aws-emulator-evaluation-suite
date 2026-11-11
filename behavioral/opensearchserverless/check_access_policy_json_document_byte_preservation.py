"""access-policy-json-document-byte-preservation."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-policy-json-document-byte-preservation"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccessPolicy returns a data access policy with nested rules, several principals and an accented
    description exactly as created, and after deletion fails with ResourceNotFoundException and its exact
    message.
    """
    osc = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = _short_name(ctx, "sim2real-accpol-")
    collection_pattern = ctx.unique_name("sim2real-accpol-data-")

    policy_document = [
        {
            "Description": 'Special chars: caf\u00e9, \u00fcml\u00e4ut, "quoted", back\\slash, tab\tend',
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [f"collection/{collection_pattern}", f"collection/{collection_pattern}-alt*"],
                    "Permission": ["aoss:CreateCollectionItems", "aoss:DescribeCollectionItems"],
                },
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{collection_pattern}/*"],
                    "Permission": ["aoss:ReadDocument", "aoss:WriteDocument"],
                },
            ],
            "Principal": [
                f"arn:aws:iam::{account_id}:role/{collection_pattern}-role",
                f"saml/{account_id}/some-provider/group/Accounting",
            ],
        }
    ]

    import json

    osc.create_access_policy(type="data", name=name, policy=json.dumps(policy_document))
    ctx.on_cleanup(lambda: _safe(lambda: osc.delete_access_policy(type="data", name=name)))

    fetched = osc.get_access_policy(type="data", name=name)["accessPolicyDetail"]["policy"]
    assert fetched == policy_document, f"policy document round trip mismatch: {fetched!r} != {policy_document!r}"

    osc.delete_access_policy(type="data", name=name)
    code, message = _error(lambda: osc.get_access_policy(type="data", name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected_message = f"Policy with name {name} and type data is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _safe(fn: Callable[[], Any]) -> None:
    """Best-effort teardown call: any error (typically not-found) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
