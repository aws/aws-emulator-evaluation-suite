"""put-registry-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-registry-policy-malformed-json-rejected"
GROUP = "negative-classes"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """Malformed registry policy JSON is rejected with InvalidParameterException rather than
    partially stored, while a well-formed policy in the same slot still succeeds (control)."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    baseline = _get_registry_policy(ecr)

    def _restore():
        try:
            ecr.delete_registry_policy()
        except ClientError as e:
            if e.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                raise
        if baseline is not None:
            ecr.put_registry_policy(policyText=baseline)

    ctx.on_cleanup(_restore)

    malformed = '{"Version": "2012-10-17", "Statement": [ this is not valid json'

    code, message = _client_error(lambda: ecr.put_registry_policy(policyText=malformed))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = (
        "Invalid parameter at 'PolicyText' failed to satisfy constraint: "
        "'Invalid registry policy provided'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: registry policy must be unchanged from baseline
    after_bad = _get_registry_policy(ecr)
    assert after_bad == baseline, (
        f"malformed policy text was partially stored: baseline={baseline!r} after={after_bad!r}"
    )

    # positive control: a well-formed policy in the very same slot succeeds
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribeControl",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:DescribeRepositories",
                "Resource": "*",
            }
        ],
    }
    good_text = json.dumps(good_policy)
    put_resp = ecr.put_registry_policy(policyText=good_text)
    assert json.loads(put_resp["policyText"]) == good_policy, (
        f"put response echo mismatch: expected {good_policy!r}, got {put_resp.get('policyText')!r}"
    )

    get_resp = ecr.get_registry_policy()
    assert json.loads(get_resp["policyText"]) == good_policy, (
        f"independent read mismatch: expected {good_policy!r}, got {get_resp.get('policyText')!r}"
    )


def _get_registry_policy(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
