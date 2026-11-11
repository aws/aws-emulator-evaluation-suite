"""identity-policy-invalid-json-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-policy-invalid-json-rejected"
GROUP = "representation"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIdentityPolicy rejects a non-JSON Policy with InvalidPolicy and does not attach it;
    a well-formed policy on the same identity attaches and reads back."""
    ses = ctx.client("ses")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    identity = ctx.unique_name("sim2real-ses-idpol-neg-") + "@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    identity_arn = f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity}"
    bad_policy_name = ctx.unique_name("sim2real-ses-pol-bad-")
    malformed_policy = '{ "Version": "2012-10-17", "Statement": [ this is not valid json'

    code, msg = _error_code(
        lambda: ses.put_identity_policy(Identity=identity, PolicyName=bad_policy_name, Policy=malformed_policy)
    )
    assert code == "InvalidPolicy", f"expected InvalidPolicy for a malformed policy document, got {code!r}: {msg!r}"
    assert msg == "Unable to parse policy.", f"expected message 'Unable to parse policy.', got {msg!r}"

    # effect absent: the malformed policy must not be attached to the identity
    names_after_failure = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert bad_policy_name not in names_after_failure, (
        f"expected {bad_policy_name!r} absent from PolicyNames, got {names_after_failure}"
    )

    # positive control: a well-formed policy attaches successfully
    good_policy_name = ctx.unique_name("sim2real-ses-pol-good-")
    principal_arn = f"arn:aws:iam::{account_id}:root"
    good_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"{principal_arn}"}},"Action":"ses:SendEmail",'
        f'"Resource":"{identity_arn}"}}]}}'
    )
    ses.put_identity_policy(Identity=identity, PolicyName=good_policy_name, Policy=good_policy)
    ctx.on_cleanup(lambda: ses.delete_identity_policy(Identity=identity, PolicyName=good_policy_name))

    names_after_success = ses.list_identity_policies(Identity=identity)["PolicyNames"]
    assert good_policy_name in names_after_success, (
        f"expected {good_policy_name!r} present in PolicyNames, got {names_after_success}"
    )
    fetched = ses.get_identity_policies(Identity=identity, PolicyNames=[good_policy_name])["Policies"]
    # SES may reformat the stored JSON (whitespace / key ordering); compare
    # semantically rather than byte-for-byte.
    import json as _json

    fetched_json = _json.loads(fetched[good_policy_name])
    expected_json = _json.loads(good_policy)
    assert fetched_json == expected_json, f"expected stored policy {expected_json}, got {fetched_json}"


def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected InvalidPolicy, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
