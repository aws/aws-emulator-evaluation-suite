"""data-quality-profile-unknown-id-rejected."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-quality-profile-unknown-id-rejected"
GROUP = "data-quality"
SERVICES = ["glue"]


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataQualityModel, GetDataQualityModelResult and PutDataQualityProfileAnnotation
    each reject, with EntityNotFoundException, a well-formed profile id that was never
    produced by a statistics run; PutDataQualityProfileAnnotation's message names that id.
    """
    glue = ctx.client("glue")

    # well-formed profile ids (the "dqprofile-" + hex shape GetDataQualityModel documents)
    # that were never produced by any statistics run
    profile_id_1 = "dqprofile-" + secrets.token_hex(20)
    profile_id_2 = "dqprofile-" + secrets.token_hex(20)

    code1, msg1 = _error(lambda: glue.get_data_quality_model(ProfileId=profile_id_1))
    assert code1 == "EntityNotFoundException", f"GetDataQualityModel gave {code1!r}, not EntityNotFoundException"
    assert msg1 == "Unable to find Model Result", f"unexpected message: {msg1!r}"

    statistic_id = "st-" + secrets.token_hex(16)
    code2, msg2 = _error(lambda: glue.get_data_quality_model_result(
        StatisticId=statistic_id, ProfileId=profile_id_1
    ))
    assert code2 == "EntityNotFoundException", f"GetDataQualityModelResult gave {code2!r}, not EntityNotFoundException"
    assert msg2 == "Unable to find Model Result", f"unexpected message: {msg2!r}"

    code3, msg3 = _error(lambda: glue.put_data_quality_profile_annotation(
        ProfileId=profile_id_1, InclusionAnnotation="INCLUDE"
    ))
    assert code3 == "EntityNotFoundException", f"PutDataQualityProfileAnnotation gave {code3!r}, not EntityNotFoundException"
    assert msg3 == f"Cannot find Data Profile in account {ctx.account} with id {profile_id_1}", (
        f"unexpected message: {msg3!r}"
    )

    # a second, differently-fabricated id gets its own id back in the message, not the first's
    code4, msg4 = _error(lambda: glue.put_data_quality_profile_annotation(
        ProfileId=profile_id_2, InclusionAnnotation="EXCLUDE"
    ))
    assert code4 == "EntityNotFoundException", f"PutDataQualityProfileAnnotation gave {code4!r}, not EntityNotFoundException"
    assert msg4 == f"Cannot find Data Profile in account {ctx.account} with id {profile_id_2}", (
        f"unexpected message: {msg4!r}"
    )
    assert msg4 != msg3, "two different unknown profile ids produced the identical error message"

    # positive control: InvalidInputException (not EntityNotFoundException) is reserved for
    # an id that is not even profile-id-shaped, confirming EntityNotFoundException above is
    # about lookup, not a generic validation failure
    code5, msg5 = _error(lambda: glue.get_data_quality_model(ProfileId="not-a-profile-id"))
    assert code5 == "InvalidInputException", f"a malformed ProfileId gave {code5!r}, not InvalidInputException"
    assert msg5 == "Invalid profileId format. Valid identifiers begin with dqprofile-", (
        f"unexpected message: {msg5!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
