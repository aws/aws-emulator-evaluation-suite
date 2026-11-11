"""op-contract-list-instance-profiles."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-instance-profiles"
GROUP = "error-semantics"
SERVICES = ["iam"]

_PATH_PREFIX_MESSAGE = (
    "The specified value for pathPrefix is invalid. It must begin with the / character and "
    "contain only alphanumeric characters and/or / characters."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstanceProfiles surfaces a freshly created profile; bad PathPrefix -> ValidationError."""
    iam = ctx.client("iam")

    profile_name = ctx.unique_name("sim2real-behav-ip-")
    created = iam.create_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    profiles = _list_all(iam.list_instance_profiles, "InstanceProfiles")
    match = next((p for p in profiles if p["InstanceProfileName"] == profile_name), None)
    assert match is not None, f"{profile_name} not found in ListInstanceProfiles output"
    assert match["Arn"] == created["Arn"], f"expected Arn {created['Arn']}, got {match['Arn']}"
    assert match["InstanceProfileId"] == created["InstanceProfileId"], (
        f"expected InstanceProfileId {created['InstanceProfileId']}, got {match['InstanceProfileId']}"
    )
    assert match["Roles"] == [], f"expected no roles on a freshly created profile, got {match['Roles']}"

    code, message = _error(lambda: iam.list_instance_profiles(PathPrefix="badpath"))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
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
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
