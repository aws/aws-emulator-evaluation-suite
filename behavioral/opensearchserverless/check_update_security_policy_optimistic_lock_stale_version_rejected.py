"""update-security-policy-optimistic-lock-stale-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-security-policy-optimistic-lock-stale-version-rejected"
GROUP = "concurrency"
SERVICES = ["opensearchserverless"]

_MALFORMED_VERSION_MESSAGE = (
    "1 validation error detected: Value 'not-a-valid-version-token!!' at 'policyVersion' failed to "
    "satisfy constraint: Member must satisfy regular expression pattern: "
    "([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?"
)
_STALE_VERSION_MESSAGE = (
    "Policy version specified in the request refers to an older version and policy has since changed"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSecurityPolicy rejects a stale/malformed policyVersion with ValidationException."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-spv-")
    policy_doc = json.dumps(
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}],
            "AWSOwnedKey": True,
        }
    )
    created = client.create_security_policy(type="encryption", name=name, policy=policy_doc)[
        "securityPolicyDetail"
    ]
    ctx.on_cleanup(lambda: client.delete_security_policy(type="encryption", name=name))
    base_version = created["policyVersion"]

    # Overly-permissive boundary: a malformed policyVersion (wrong length/pattern) is rejected.
    code, message = _error(
        lambda: client.update_security_policy(
            type="encryption",
            name=name,
            policyVersion="not-a-valid-version-token!!",
            description="should-not-apply",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed policyVersion, got {code!r}"
    )
    assert message == _MALFORMED_VERSION_MESSAGE, (
        f"expected message {_MALFORMED_VERSION_MESSAGE!r}, got {message!r}"
    )

    v1 = client.update_security_policy(
        type="encryption",
        name=name,
        policyVersion=base_version,
        policy=json.dumps(
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/{name}", f"collection/{name}-2"]}
                ],
                "AWSOwnedKey": True,
            }
        ),
        description="updated-once",
    )["securityPolicyDetail"]
    current_version = v1["policyVersion"]
    assert current_version != base_version, "policyVersion should change after a successful update"

    # Break exactly one thing: reuse the now-stale (already-consumed) base_version.
    code, message = _error(
        lambda: client.update_security_policy(
            type="encryption",
            name=name,
            policyVersion=base_version,
            policy=json.dumps(
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{name}", f"collection/{name}-2", f"collection/{name}-3"],
                        }
                    ],
                    "AWSOwnedKey": True,
                }
            ),
            description="updated-with-stale-version",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a stale (already-consumed) policyVersion, got {code!r}"
    )
    assert message == _STALE_VERSION_MESSAGE, (
        f"expected message {_STALE_VERSION_MESSAGE!r}, got {message!r}"
    )

    # Effect must be absent: the rejected call's description never persisted.
    got = client.get_security_policy(type="encryption", name=name)["securityPolicyDetail"]
    assert got["description"] == "updated-once", (
        f"expected the stale-version update's description to not persist, got {got['description']!r}"
    )
    assert got["policyVersion"] == current_version, (
        f"expected policyVersion to remain {current_version!r} after the rejected update, "
        f"got {got['policyVersion']!r}"
    )

    # Positive control: the correct (current) version is still accepted (change the
    # policy content again so the version is guaranteed to mint anew).
    final = client.update_security_policy(
        type="encryption",
        name=name,
        policyVersion=current_version,
        policy=json.dumps(
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [
                            f"collection/{name}",
                            f"collection/{name}-2",
                            f"collection/{name}-3",
                            f"collection/{name}-4",
                        ],
                    }
                ],
                "AWSOwnedKey": True,
            }
        ),
        description="updated-twice",
    )["securityPolicyDetail"]
    assert final["description"] == "updated-twice", (
        f"expected the restored update's description to be 'updated-twice', got {final['description']!r}"
    )
    assert final["policyVersion"] != current_version, (
        f"expected policyVersion to advance past {current_version!r} after the restored update"
    )

    # Independent terminal read at the destination: the restored update's effect is
    # visible through GetSecurityPolicy, not just in UpdateSecurityPolicy's own response.
    final_read = client.get_security_policy(type="encryption", name=name)["securityPolicyDetail"]
    assert final_read["description"] == "updated-twice", (
        f"expected GetSecurityPolicy to reflect 'updated-twice', got {final_read['description']!r}"
    )
    assert final_read["policyVersion"] == final["policyVersion"], (
        f"expected GetSecurityPolicy's policyVersion {final_read['policyVersion']!r} to match "
        f"UpdateSecurityPolicy's returned {final['policyVersion']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
