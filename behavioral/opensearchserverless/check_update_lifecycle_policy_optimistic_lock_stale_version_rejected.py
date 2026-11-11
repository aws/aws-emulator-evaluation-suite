"""update-lifecycle-policy-optimistic-lock-stale-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-lifecycle-policy-optimistic-lock-stale-version-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateLifecyclePolicy rejects a stale/malformed policyVersion with ValidationException."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-lpv-")
    policy_doc = json.dumps(
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{name}/*"],
                    "MinIndexRetention": "24h",
                }
            ]
        }
    )
    created = client.create_lifecycle_policy(type="retention", name=name, policy=policy_doc)[
        "lifecyclePolicyDetail"
    ]
    ctx.on_cleanup(lambda: client.delete_lifecycle_policy(type="retention", name=name))
    base_version = created["policyVersion"]

    # Overly-permissive boundary: a malformed policyVersion (wrong length/pattern) is rejected.
    code, message = _error(
        lambda: client.update_lifecycle_policy(
            type="retention",
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

    v1 = client.update_lifecycle_policy(
        type="retention",
        name=name,
        policyVersion=base_version,
        policy=json.dumps(
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{name}/*"],
                        "MinIndexRetention": "48h",
                    }
                ]
            }
        ),
        description="updated-once",
    )["lifecyclePolicyDetail"]
    current_version = v1["policyVersion"]
    assert current_version != base_version, "policyVersion should change after a successful update"

    # Break exactly one thing: reuse the now-stale (already-consumed) base_version.
    code, message = _error(
        lambda: client.update_lifecycle_policy(
            type="retention",
            name=name,
            policyVersion=base_version,
            policy=json.dumps(
                {
                    "Rules": [
                        {
                            "ResourceType": "index",
                            "Resource": [f"index/{name}/*"],
                            "MinIndexRetention": "72h",
                        }
                    ]
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
    fetched = client.batch_get_lifecycle_policy(
        identifiers=[{"type": "retention", "name": name}]
    )
    details = fetched.get("lifecyclePolicyDetails", [])
    assert len(details) == 1, f"expected exactly one lifecycle policy, got {details}"
    assert details[0]["description"] == "updated-once"
    assert details[0]["policyVersion"] == current_version

    # Positive control: the correct (current) version is still accepted (change the
    # policy content again so the version is guaranteed to mint anew).
    final = client.update_lifecycle_policy(
        type="retention",
        name=name,
        policyVersion=current_version,
        policy=json.dumps(
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{name}/*"],
                        "MinIndexRetention": "96h",
                    }
                ]
            }
        ),
        description="updated-twice",
    )["lifecyclePolicyDetail"]
    assert final["description"] == "updated-twice"
    final_version = final["policyVersion"]
    assert final_version != current_version

    # Terminal read is independent of the mutating call: confirm the accepted
    # update actually persisted, at the destination.
    refetched = client.batch_get_lifecycle_policy(
        identifiers=[{"type": "retention", "name": name}]
    )["lifecyclePolicyDetails"]
    assert len(refetched) == 1, f"expected exactly one lifecycle policy, got {refetched}"
    assert refetched[0]["description"] == "updated-twice"
    assert refetched[0]["policyVersion"] == final_version


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
