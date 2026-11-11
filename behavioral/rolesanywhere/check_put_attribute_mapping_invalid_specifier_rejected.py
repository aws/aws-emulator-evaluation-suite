"""put-attribute-mapping-invalid-specifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-attribute-mapping-invalid-specifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributeMapping with specifier CN for certificateField x509SAN (which supports only DNS,
    URI and Name) is refused with ValidationException and persists nothing, while a supported
    specifier on the same profile is accepted.
    """
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
        tags=[{"key": "sim2real", "value": "true"}],
    )["profile"]
    profile_id = profile["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    error = _client_error(
        lambda: ra.put_attribute_mapping(
            profileId=profile_id,
            certificateField="x509SAN",
            mappingRules=[{"specifier": "CN"}],
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected_message = "Unable to validate specifier (CN) on the target (SUBJECT_ALTERNATIVE_NAME)"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    got = ra.get_profile(profileId=profile_id)["profile"]
    san_entry = _find_mapping(got["attributeMappings"], "x509SAN")
    if san_entry is not None:
        assert {"specifier": "CN"} not in san_entry["mappingRules"], (
            f"CN specifier leaked into x509SAN mapping despite ValidationException: "
            f"{san_entry['mappingRules']!r}"
        )

    # Positive control: same profile, a supported x509SAN specifier, succeeds.
    ra.put_attribute_mapping(
        profileId=profile_id,
        certificateField="x509SAN",
        mappingRules=[{"specifier": "DNS"}],
    )
    got_after = ra.get_profile(profileId=profile_id)["profile"]
    san_entry_after = _find_mapping(got_after["attributeMappings"], "x509SAN")
    assert san_entry_after is not None, "expected an x509SAN mapping after a successful PutAttributeMapping"
    assert {"specifier": "DNS"} in san_entry_after["mappingRules"], (
        f"expected DNS specifier in x509SAN mapping, got {san_entry_after['mappingRules']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected PutAttributeMapping to be rejected, but it SUCCEEDED: {result!r}")


def _find_mapping(mappings, certificate_field: str):
    for entry in mappings:
        if entry.get("certificateField") == certificate_field:
            return entry
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
