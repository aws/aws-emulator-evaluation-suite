"""alert-requires-an-explicit-assume-access-profile-trust-grant."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alert-requires-an-explicit-assume-access-profile-trust-grant"
GROUP = 'access-control'
SERVICES = ['cloudwatchomni']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_TELEMETRY_RULE = {
    "query": {"language": "SQL", "expression": "SELECT 1"},
    "condition": {"thresholdMode": "COUNT_OF_RESULTS", "comparator": "GT", "criticalThreshold": 90.0},
    "evaluation": {"intervalSeconds": 300},
    "noData": {"treatAs": "NODATA"},
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """A grant naming an access profile as its principal round-trips through
    CreateAccessGrant/GetAccessGrant, and an alert naming that profile is refused for lacking
    the separate ALERT-principal trust grant the profile needs before any alert may assume it.
    """
    cwo = ctx.client("cloudwatchomni")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    domain_id = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]["domainId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain_id), "ResourceNotFoundException"))

    space_id = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]["spaceId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space_id),
                             "ResourceNotFoundException", "AccessDeniedException"))

    profile_name = ctx.unique_name("sim2real-behav-cwo-prof-")
    profile = cwo.create_access_profile(spaceId=space_id, name=profile_name, description="behavioral probe")[
        "accessProfile"
    ]
    profile_id = profile["profileId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_access_profile(spaceId=space_id, profileId=profile_id),
                             "ResourceNotFoundException"))
    assert profile["name"] == profile_name, f"expected name {profile_name!r}, got {profile['name']!r}"

    got_profile = cwo.get_access_profile(spaceId=space_id, profileId=profile_id)["accessProfile"]
    assert got_profile["profileId"] == profile_id, (
        f"expected {profile_id!r}, got {got_profile['profileId']!r}"
    )
    assert got_profile["name"] == profile_name, f"expected {profile_name!r}, got {got_profile['name']!r}"

    grant_name = ctx.unique_name("sim2real-behav-cwo-grant-")
    grant = cwo.create_access_grant(
        domainId=domain_id,
        spaceId=space_id,
        name=grant_name,
        principal={"principalType": "ACCESS_PROFILE", "principalId": profile_id},
        permission="READ",
    )["accessGrant"]
    grant_id = grant["grantId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_access_grant(grantId=grant_id), "ResourceNotFoundException"))
    assert grant["permission"] == "READ", f"expected READ, got {grant['permission']!r}"
    assert grant["principal"]["principalId"] == profile_id, (
        f"expected principalId {profile_id!r}, got {grant['principal']['principalId']!r}"
    )

    got_grant = cwo.get_access_grant(grantId=grant_id)["accessGrant"]
    assert got_grant["grantId"] == grant_id, f"expected {grant_id!r}, got {got_grant['grantId']!r}"
    assert got_grant["name"] == grant_name, f"expected {grant_name!r}, got {got_grant['name']!r}"

    alert_name = ctx.unique_name("sim2real-behav-cwo-alert-")
    code, message = _error(
        lambda: cwo.create_alert(
            spaceId=space_id, profileId=profile_id, name=alert_name, rule={"telemetryRule": _TELEMETRY_RULE}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        f"The alert cannot assume access profile {profile_id}. Grant the profile a trust grant "
        "with principalType=ALERT (customAction cloudwatch:AssumeAccessProfile) before creating "
        "the alert."
    ), f"unexpected message {message!r}"

    cwo.delete_access_grant(grantId=grant_id)
    code, _ = _error(lambda: cwo.get_access_grant(grantId=grant_id))
    assert code == "ResourceNotFoundException", f"expected gone after delete, got {code}"

    cwo.delete_access_profile(spaceId=space_id, profileId=profile_id)
    code, _ = _error(lambda: cwo.get_access_profile(spaceId=space_id, profileId=profile_id))
    assert code == "ResourceNotFoundException", f"expected gone after delete, got {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
