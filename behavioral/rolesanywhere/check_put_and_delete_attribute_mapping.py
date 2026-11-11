"""put-and-delete-attribute-mapping."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-and-delete-attribute-mapping"
GROUP = "data-plane"
SERVICES = ["rolesanywhere"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributeMapping adds specifiers to a certificateField's rules; a scoped
    DeleteAttributeMapping removes only the named specifier and leaves any other
    specifier on that same certificateField intact."""
    ra = ctx.client("rolesanywhere")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"

    profile = ra.create_profile(
        name=ctx.unique_name("sim2real-ra-profile-"),
        roleArns=[role_arn],
    )["profile"]
    profile_id = profile["profileId"]
    ctx.on_cleanup(lambda: ra.delete_profile(profileId=profile_id))

    ra.put_attribute_mapping(
        profileId=profile_id,
        certificateField="x509Subject",
        mappingRules=[{"specifier": "CN"}, {"specifier": "O"}],
    )

    after_put = ra.get_profile(profileId=profile_id)["profile"]
    subject_entry = _find_mapping(after_put["attributeMappings"], "x509Subject")
    assert subject_entry is not None, "expected an x509Subject mapping entry after PutAttributeMapping"
    assert {"specifier": "CN"} in subject_entry["mappingRules"], (
        f"expected CN specifier in {subject_entry['mappingRules']}"
    )
    assert {"specifier": "O"} in subject_entry["mappingRules"], (
        f"expected O specifier in {subject_entry['mappingRules']}"
    )

    ra.delete_attribute_mapping(
        profileId=profile_id,
        certificateField="x509Subject",
        specifiers=["CN"],
    )

    after_delete = ra.get_profile(profileId=profile_id)["profile"]
    subject_entry_after = _find_mapping(after_delete["attributeMappings"], "x509Subject")
    assert subject_entry_after is not None, (
        "expected the x509Subject mapping entry to survive: the O specifier was never deleted"
    )
    assert {"specifier": "CN"} not in subject_entry_after["mappingRules"], (
        f"deleted CN specifier still present in {subject_entry_after['mappingRules']}"
    )
    assert {"specifier": "O"} in subject_entry_after["mappingRules"], (
        f"scoped delete of CN removed the untouched O specifier too: {subject_entry_after['mappingRules']}"
    )


def _find_mapping(mappings, certificate_field: str):
    for entry in mappings:
        if entry.get("certificateField") == certificate_field:
            return entry
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
