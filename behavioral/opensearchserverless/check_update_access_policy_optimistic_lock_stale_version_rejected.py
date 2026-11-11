"""update-access-policy-optimistic-lock-stale-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-access-policy-optimistic-lock-stale-version-rejected"
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
    """UpdateAccessPolicy rejects a stale/malformed policyVersion with ValidationException."""
    client = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-apv-")
    policy_doc = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{name}"],
                        "Permission": ["aoss:DescribeCollectionItems"],
                    }
                ],
                "Principal": [f"arn:aws:iam::{account_id}:role/{name}-role"],
            }
        ]
    )
    created = client.create_access_policy(type="data", name=name, policy=policy_doc)[
        "accessPolicyDetail"
    ]
    ctx.on_cleanup(lambda: client.delete_access_policy(type="data", name=name))
    base_version = created["policyVersion"]

    # Overly-permissive boundary: a malformed policyVersion (wrong length/pattern) is rejected.
    code, message = _error(
        lambda: client.update_access_policy(
            type="data",
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

    # Content must actually change -- policyVersion is a hash of the policy document,
    # so a description-only update with an unchanged policy body does not mint a new
    # version.
    updated_policy_doc = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{name}"],
                        "Permission": [
                            "aoss:DescribeCollectionItems",
                            "aoss:CreateCollectionItems",
                        ],
                    }
                ],
                "Principal": [f"arn:aws:iam::{account_id}:role/{name}-role"],
            }
        ]
    )
    v1 = client.update_access_policy(
        type="data",
        name=name,
        policyVersion=base_version,
        policy=updated_policy_doc,
        description="updated-once",
    )["accessPolicyDetail"]
    current_version = v1["policyVersion"]
    assert current_version != base_version, "policyVersion should change after a successful update"

    # Break exactly one thing: reuse the now-stale (already-consumed) base_version.
    updated_policy_doc_2 = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{name}"],
                        "Permission": [
                            "aoss:DescribeCollectionItems",
                            "aoss:CreateCollectionItems",
                            "aoss:UpdateCollectionItems",
                        ],
                    }
                ],
                "Principal": [f"arn:aws:iam::{account_id}:role/{name}-role"],
            }
        ]
    )
    code, message = _error(
        lambda: client.update_access_policy(
            type="data",
            name=name,
            policyVersion=base_version,
            policy=updated_policy_doc_2,
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
    got = client.get_access_policy(type="data", name=name)["accessPolicyDetail"]
    assert got["description"] == "updated-once", (
        f"expected the rejected update's description to never persist, got {got['description']!r}"
    )
    assert got["policyVersion"] == current_version, (
        f"expected policyVersion to remain {current_version!r} after the rejected update, "
        f"got {got['policyVersion']!r}"
    )

    # Positive control: the correct (current) version is still accepted (change the
    # policy content again so the version is guaranteed to mint anew).
    final = client.update_access_policy(
        type="data",
        name=name,
        policyVersion=current_version,
        policy=json.dumps(
            [
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{name}"],
                            "Permission": [
                                "aoss:DescribeCollectionItems",
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                            ],
                        }
                    ],
                    "Principal": [f"arn:aws:iam::{account_id}:role/{name}-role"],
                }
            ]
        ),
        description="updated-twice",
    )["accessPolicyDetail"]
    assert final["description"] == "updated-twice", (
        f"expected the accepted update's own response to reflect the new description, "
        f"got {final['description']!r}"
    )
    assert final["policyVersion"] != current_version, (
        "expected a fresh policyVersion after a successful update, "
        f"got the same version {final['policyVersion']!r}"
    )

    # Terminal read: independent of the mutating call, at the destination.
    final_read = client.get_access_policy(type="data", name=name)["accessPolicyDetail"]
    assert final_read["description"] == "updated-twice", (
        f"expected an independent read to see the accepted update's description, "
        f"got {final_read['description']!r}"
    )
    assert final_read["policyVersion"] == final["policyVersion"], (
        f"expected an independent read to report policyVersion {final['policyVersion']!r}, "
        f"got {final_read['policyVersion']!r}"
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
