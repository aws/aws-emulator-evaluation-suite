"""op-contract-listInstanceProfiles-path-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listInstanceProfiles-path-prefix"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PathPrefix filtering returns exactly the instance profile the check created; MaxItems=1001 is
    rejected server-side with the exact ValidationError message."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-batch09-ip")
    path = f"/{suffix}/"
    profile_name = f"{suffix}-profile"
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Path=path,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    resp = iam.list_instance_profiles(PathPrefix=path)
    names = [p["InstanceProfileName"] for p in resp["InstanceProfiles"]]
    assert names == [profile_name], f"expected exactly [{profile_name}], got {names}"
    assert resp["InstanceProfiles"][0]["Roles"] == []
    assert resp["InstanceProfiles"][0]["Path"] == path

    # Error boundary: MaxItems above the documented valid maximum of 1000 is rejected by the
    # service as a ValidationError (not caught client-side by botocore's param validation).
    try:
        iam.list_instance_profiles(MaxItems=1001)
        raise AssertionError("expected ValidationError for MaxItems=1001")
    except ClientError as exc:
        error = exc.response["Error"]
    assert error["Code"] == "ValidationError", error["Code"]
    expected = (
        "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
