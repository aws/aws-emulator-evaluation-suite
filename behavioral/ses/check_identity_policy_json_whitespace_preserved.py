"""identity-policy-json-whitespace-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-policy-json-whitespace-preserved"
GROUP = "representation"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy submitted with irregular whitespace round-trips semantically through
    GetIdentityPolicies; the stored JSON may be re-serialized (no stored form is documented)."""
    ses = ctx.client("ses")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    identity = ctx.unique_name("sim2real-ses-idpol-") + "@example.com"
    ses.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=identity))

    identity_arn = f"arn:aws:ses:{ctx.region}:{account_id}:identity/{identity}"
    principal_arn = f"arn:aws:iam::{account_id}:root"
    policy_name = ctx.unique_name("sim2real-ses-pol-")
    policy_text = (
        "{\n"
        '    "Version"   :   "2012-10-17",\n'
        '    "Statement": [\n'
        "        {\n"
        '            "Effect": "Allow",\n'
        f'            "Principal": {{"AWS": "{principal_arn}"}},\n'
        '            "Action": "ses:SendEmail",\n'
        f'            "Resource": "{identity_arn}"\n'
        "        }\n"
        "    ]\n"
        "}\n"
    )
    ses.put_identity_policy(Identity=identity, PolicyName=policy_name, Policy=policy_text)
    ctx.on_cleanup(lambda: ses.delete_identity_policy(Identity=identity, PolicyName=policy_name))

    got = ses.get_identity_policies(Identity=identity, PolicyNames=[policy_name])["Policies"][policy_name]
    import json as _json

    got_parsed = _json.loads(got)
    expected_parsed = _json.loads(policy_text)
    assert got_parsed == expected_parsed, (got, policy_text)
    stmt = got_parsed["Statement"][0]
    assert stmt["Effect"] == "Allow", f"expected Effect=Allow, got {stmt.get('Effect')!r}"
    assert stmt["Principal"]["AWS"] == principal_arn, (
        f"expected Principal.AWS={principal_arn!r}, got {stmt['Principal'].get('AWS')!r}"
    )
    assert stmt["Action"] == "ses:SendEmail", f"expected Action=ses:SendEmail, got {stmt.get('Action')!r}"
    assert stmt["Resource"] == identity_arn, f"expected Resource={identity_arn!r}, got {stmt.get('Resource')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
