"""security-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-configuration-lifecycle"
GROUP = 'security-configuration'
SERVICES = ['glue']

def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """security_configuration create -> get -> list -> delete -> recreate, preserving encryption
    modes and confirming the freed name is reusable."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-seccfg-")
    glue.create_security_configuration(
        Name=name,
        EncryptionConfiguration={
            "S3Encryption": [{"S3EncryptionMode": "SSE-S3"}],
            "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"},
            "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"},
        },
    )
    ctx.on_cleanup(lambda: glue.delete_security_configuration(Name=name))

    cfg = glue.get_security_configuration(Name=name)["SecurityConfiguration"]
    assert cfg["Name"] == name
    modes = [e["S3EncryptionMode"] for e in cfg["EncryptionConfiguration"]["S3Encryption"]]
    assert modes == ["SSE-S3"], f"S3 encryption mode not persisted: {cfg}"

    names = {c["Name"] for c in glue.get_security_configurations()["SecurityConfigurations"]}
    assert name in names, "security configuration missing from GetSecurityConfigurations"

    glue.delete_security_configuration(Name=name)
    code, message = _refusal(lambda: glue.get_security_configuration(Name=name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteSecurityConfiguration, got {code}"
    )
    assert message == "", message

    # the freed name must be immediately reusable, not left reserved by the deleted configuration
    glue.create_security_configuration(
        Name=name,
        EncryptionConfiguration={
            "S3Encryption": [{"S3EncryptionMode": "SSE-S3"}],
            "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"},
            "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"},
        },
    )
    recreated = glue.get_security_configuration(Name=name)["SecurityConfiguration"]
    assert recreated["Name"] == name, f"deleted security configuration name not reusable: {recreated}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
