"""use-case-for-model-access-put-get-roundtrip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "use-case-for-model-access-put-get-roundtrip"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-model-access-use-case")
def run(ctx) -> None:
    """GetUseCaseForModelAccess returns the exact bytes PutUseCaseForModelAccess stored; where AWS refuses
    the Put with AccessDeniedException for internal accounts, the stored form (or its absence) is unchanged.
    """

    bedrock = ctx.client("bedrock")

    # Positive control: the account and credentials are otherwise healthy for Bedrock,
    # so a downstream AccessDeniedException comes from the Put itself.
    bedrock.list_foundation_models()

    original_form: bytes | None = None
    try:
        original_form = bedrock.get_use_case_for_model_access()["formData"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    def _restore() -> None:
        if original_form is not None:
            bedrock.put_use_case_for_model_access(formData=original_form)

    ctx.on_cleanup(_restore)

    form = {
        "companyName": ctx.unique_name("sim2real-acme-"),
        "companyWebsite": "https://example.com",
        "intendedUsers": "Internal QA team running automated behavioral fidelity checks",
        "industryOption": "Other",
        "otherIndustryOption": "Software Testing",
        "useCases": "Automated verification of Bedrock account-level model access acknowledgement",
    }
    form_bytes = json.dumps(form).encode("utf-8")

    try:
        bedrock.put_use_case_for_model_access(formData=form_bytes)
    except ClientError as err:
        message = err.response["Error"].get("Message", "")
        if err.response["Error"]["Code"] == "AccessDeniedException" and "Internal Accounts" in message:
            # AWS refuses this call for internal accounts. An independent read shows the
            # stored form (or its absence) exactly as it was before the refused Put.
            after: bytes | None = None
            try:
                after = bedrock.get_use_case_for_model_access()["formData"]
            except ClientError as err2:
                if err2.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            assert after == original_form, (
                "GetUseCaseForModelAccess changed after a Put that AWS refused with "
                f"AccessDeniedException ('Internal Accounts...'): {after!r} != {original_form!r}"
            )
            return
        raise

    got = bedrock.get_use_case_for_model_access()["formData"]
    assert got == form_bytes, (
        f"GetUseCaseForModelAccess returned different bytes than were Put: {got!r} != {form_bytes!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
