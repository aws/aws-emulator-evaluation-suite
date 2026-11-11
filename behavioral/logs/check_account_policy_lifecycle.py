"""account-policy-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]

_POLICY_TYPE = "DATA_PROTECTION_POLICY"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """PutAccountPolicy creates an account-scoped policy visible via DescribeAccountPolicies
    and removable via DeleteAccountPolicy."""
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-acct-policy-")

    # Account policies of a given type are a singleton per account/region. If one already
    # exists (real production usage, or a leaked run) we cannot safely clobber it.
    existing = logs.describe_account_policies(policyType=_POLICY_TYPE).get("accountPolicies", [])
    if existing:
        raise AssertionError(
            f"account already has a {_POLICY_TYPE} account policy "
            f"({existing[0].get('policyName')!r}); cannot create a second one"
        )

    policy_document = {
        "Name": "sim2real-behav-data-protection",
        "Version": "2021-06-01",
        "Statement": [
            {
                "Sid": "audit-email",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Audit": {"FindingsDestination": {}}},
            },
            {
                "Sid": "redact-email",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Deidentify": {"MaskConfig": {}}},
            },
        ],
    }

    put_resp = logs.put_account_policy(
        policyName=name,
        policyDocument=json.dumps(policy_document),
        policyType=_POLICY_TYPE,
    )
    ctx.on_cleanup(lambda: _delete_if_present(logs, name))

    assert put_resp["accountPolicy"]["policyName"] == name, (
        f"expected PutAccountPolicy to echo policyName {name!r}, "
        f"got {put_resp['accountPolicy'].get('policyName')!r}"
    )
    assert put_resp["accountPolicy"]["policyType"] == _POLICY_TYPE, (
        f"expected PutAccountPolicy to echo policyType {_POLICY_TYPE!r}, "
        f"got {put_resp['accountPolicy'].get('policyType')!r}"
    )

    described = logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=name)
    policies = described.get("accountPolicies", [])
    assert len(policies) == 1, f"expected exactly 1 account policy, got {policies}"
    assert policies[0]["policyName"] == name, (
        f"expected the described policy to be named {name!r}, got {policies[0].get('policyName')!r}"
    )
    round_tripped = json.loads(policies[0]["policyDocument"])
    assert round_tripped["Statement"][0]["Sid"] == "audit-email", (
        f"expected the round-tripped policy document's first statement Sid to be "
        f"'audit-email', got {round_tripped['Statement'][0].get('Sid')!r}"
    )

    logs.delete_account_policy(policyName=name, policyType=_POLICY_TYPE)

    for _ in range(10):
        remaining = logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=name)
        if not remaining.get("accountPolicies"):
            break
        time.sleep(1.0)
    else:
        raise AssertionError("account policy still visible after DeleteAccountPolicy")

    # The id is now dead: a mutation against it (a repeat delete) must fail specifically,
    # not silently no-op.
    code, message = _error(
        lambda: logs.delete_account_policy(policyName=name, policyType=_POLICY_TYPE)
    )
    assert code == "ResourceNotFoundException", (
        f"expected a repeat DeleteAccountPolicy on the already-deleted policy {name!r} to "
        f"fail with ResourceNotFoundException, got {code!r}"
    )
    expected_message = "Specified resource does not exists!"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _delete_if_present(logs, name):
    """Teardown: delete the account policy; the check itself deletes it on the happy path."""
    try:
        logs.delete_account_policy(policyName=name, policyType=_POLICY_TYPE)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
