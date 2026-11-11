"""op-contract-list-policies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-policies"
GROUP = "error-semantics"
SERVICES = ["iam"]

_PATH_PREFIX_MESSAGE = (
    "The specified value for pathPrefix is invalid. It must begin with the / character and "
    "contain only alphanumeric characters and/or / characters."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies(Scope=Local) surfaces a freshly created customer-managed policy;
    malformed PathPrefix -> ValidationError."""
    iam = ctx.client("iam")

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    created = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=created["Arn"]))

    policies = _list_all(iam.list_policies, "Policies", Scope="Local")
    match = next((p for p in policies if p["PolicyName"] == policy_name), None)
    assert match is not None, f"{policy_name} not found in ListPolicies(Scope=Local) output"
    assert match["Arn"] == created["Arn"], f"listed Arn {match['Arn']!r} != created Arn {created['Arn']!r}"
    assert match["PolicyId"] == created["PolicyId"], (
        f"listed PolicyId {match['PolicyId']!r} != created PolicyId {created['PolicyId']!r}"
    )
    assert match["IsAttachable"] is True, f"expected IsAttachable True, got {match['IsAttachable']!r}"
    assert match["DefaultVersionId"] == created["DefaultVersionId"], (
        f"listed DefaultVersionId {match['DefaultVersionId']!r} != "
        f"created DefaultVersionId {created['DefaultVersionId']!r}"
    )

    code, message = _error(lambda: iam.list_policies(PathPrefix="badpath"))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == _PATH_PREFIX_MESSAGE, f"expected message {_PATH_PREFIX_MESSAGE!r}, got {message!r}"


def _list_all(fn, list_key, **kwargs):
    items = []
    marker = None
    while True:
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        resp = fn(**params)
        items.extend(resp.get(list_key, []))
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
    return items


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
