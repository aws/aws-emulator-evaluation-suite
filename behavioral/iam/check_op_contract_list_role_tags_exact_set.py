"""op-contract-listRoleTags-exact-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listRoleTags-exact-set"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Success path returns exactly the tags the role was created with; a missing role yields
    NoSuchEntityException; and a deleted role loses both its tags and its ability to be tagged."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch09-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-batch", "Value": "09"}, {"Key": "team", "Value": "iam-checks"}],
    )
    ctx.on_cleanup(lambda: _delete_role_if_present(iam, role_name))

    resp = iam.list_role_tags(RoleName=role_name)
    tag_map = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_map == {"sim2real-batch": "09", "team": "iam-checks"}, tag_map
    assert resp["IsTruncated"] is False, f"expected IsTruncated False, got {resp['IsTruncated']!r}"

    # Error boundary: RoleName that never existed.
    bogus_role = ctx.unique_name("sim2real-batch09-missing-role-")
    error = _client_error(lambda: iam.list_role_tags(RoleName=bogus_role))
    assert error.get("Code") == "NoSuchEntity", f"expected NoSuchEntity, got {error!r}"
    expected = f"The role with name {bogus_role} cannot be found."
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error!r}"

    # Delete proves gone: the role that had tags a moment ago now answers NoSuchEntity too, and a
    # mutation on the dead id (TagRole) fails the same way.
    iam.delete_role(RoleName=role_name)
    gone = f"The role with name {role_name} cannot be found."
    error = _client_error(lambda: iam.list_role_tags(RoleName=role_name))
    assert error.get("Code") == "NoSuchEntity", f"expected NoSuchEntity after delete, got {error!r}"
    assert error.get("Message") == gone, f"expected message {gone!r} after delete, got {error!r}"
    error = _client_error(
        lambda: iam.tag_role(RoleName=role_name, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert error.get("Code") == "NoSuchEntity", (
        f"expected NoSuchEntity for TagRole on a deleted role, got {error!r}"
    )
    assert error.get("Message") == gone, (
        f"expected message {gone!r} for TagRole on a deleted role, got {error!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting a call
    AWS refuses never reads as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_role_if_present(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
