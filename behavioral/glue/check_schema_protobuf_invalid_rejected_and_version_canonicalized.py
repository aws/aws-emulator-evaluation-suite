"""schema-protobuf-invalid-rejected-and-version-canonicalized."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-protobuf-invalid-rejected-and-version-canonicalized"
GROUP = 'overly-permissive'
SERVICES = ['glue']

PROTOBUF_VALID = (
    'syntax = "proto3";\n'
    "package com.sim2real;\n"
    "message Customer {\n"
    "  int64 id = 1;\n"
    "  string email = 2;\n"
    "}\n"
)

# Semantically identical to PROTOBUF_VALID, differing only in whitespace -- the
# canonicalization this check is after must treat these as the same schema content.
PROTOBUF_VALID_RESPACED = (
    'syntax   =   "proto3";\n\n'
    "package com.sim2real;\n\n\n"
    "message Customer {\n"
    "    int64 id = 1;\n"
    "    string email = 2;\n"
    "}\n"
)

# Missing the semicolon terminating the first field -- malformed protobuf, not merely a
# different-but-valid schema.
PROTOBUF_INVALID = (
    'syntax = "proto3";\n'
    "package com.sim2real;\n"
    "message Customer {\n"
    "  int64 id = 1\n"
    "  string email = 2;\n"
    "}\n"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed PROTOBUF definition is reported invalid with the parser's error and refused by
    CreateSchema; re-registering a whitespace-only respacing returns the same SchemaVersionId at
    VersionNumber 1 instead of minting a new version.
    """
    glue = ctx.client("glue")

    # Positive control: a well-formed PROTOBUF schema is reported valid.
    control = glue.check_schema_version_validity(
        DataFormat="PROTOBUF", SchemaDefinition=PROTOBUF_VALID
    )
    assert control["Valid"] is True, f"a well-formed PROTOBUF schema must be valid: {control}"

    invalid = glue.check_schema_version_validity(
        DataFormat="PROTOBUF", SchemaDefinition=PROTOBUF_INVALID
    )
    assert invalid["Valid"] is False, (
        f"a malformed PROTOBUF definition must not be reported valid: {invalid}"
    )
    # Line 5 of PROTOBUF_INVALID is the field missing its ';'; column 4 is where the next field
    # starts, which is where the parser reports the omission.
    want_error = "Syntax error in :5:4: expected ';'"
    assert invalid["Error"] == want_error, (
        f"an invalid PROTOBUF definition must come with the parser's Error {want_error!r}: {invalid}"
    )

    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    bad_name = ctx.unique_name("sim2real-behav-protobuf-bad-")
    code, message = _refusal(lambda: glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=bad_name,
        DataFormat="PROTOBUF",
        Compatibility="NONE",
        SchemaDefinition=PROTOBUF_INVALID,
        Tags={"sim2real": CHECK},
    ))
    want = f"Schema definition of PROTOBUF data format is invalid: {want_error}"
    assert (code, message) == ("InvalidInputException", want), (
        f"create_schema on a malformed PROTOBUF definition answered {(code, message)!r}, "
        f"expected {('InvalidInputException', want)!r}"
    )

    schema_name = ctx.unique_name("sim2real-behav-protobuf-ok-")
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_name,
        DataFormat="PROTOBUF",
        Compatibility="BACKWARD",
        SchemaDefinition=PROTOBUF_VALID,
        Tags={"sim2real": CHECK},
    )
    assert created["LatestSchemaVersion"] == 1, (
        f"a freshly created schema must report LatestSchemaVersion 1: {created}"
    )

    schema_id = {"RegistryName": registry, "SchemaName": schema_name}
    reregistered = glue.register_schema_version(
        SchemaId=schema_id,
        SchemaDefinition=PROTOBUF_VALID_RESPACED,
    )
    assert reregistered["SchemaVersionId"] == created["SchemaVersionId"], (
        f"a whitespace-only respacing of the same PROTOBUF content must canonicalize to the same "
        f"SchemaVersionId, got {reregistered['SchemaVersionId']!r} != {created['SchemaVersionId']!r}"
    )
    assert reregistered["VersionNumber"] == 1, (
        f"a respaced-but-identical PROTOBUF definition must not mint a new version, got "
        f"VersionNumber={reregistered['VersionNumber']!r}"
    )

    # Independent read confirms there is still exactly one version on disk, not two.
    versions = glue.list_schema_versions(SchemaId=schema_id)["Schemas"]
    version_numbers = sorted(v["VersionNumber"] for v in versions)
    assert version_numbers == [1], (
        f"canonicalization must leave exactly one version, got {version_numbers}"
    )


def _refusal(fn) -> tuple[str, str]:
    """The (code, message) fn() raises. RAISES when the call succeeds: real AWS rejects it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call succeeded where real AWS rejects it: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
