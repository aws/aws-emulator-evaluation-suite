"""put-metadata-flag-unknown-feature-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metadata-flag-unknown-feature-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"
_VALID_FEATURE = "autoGenerateForms"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetadataFlag rejects a featureName outside the set GetMetadata reports with an HTTP 400 naming
    the feature as invalid, while the same call for a known feature succeeds and shows in GetMetadata."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")

    unknown_feature = "someUnknownFeature"
    code, message = _error_code_and_message(
        lambda: uib.put_metadata_flag(
            appId=app_id,
            environmentName=_ENV,
            featureName=unknown_feature,
            body={"newValue": "true"},
        )
    )
    assert code == "400", f"expected an HTTP 400 for an unrecognized feature name, got {code}"
    assert message == f"Feature {unknown_feature} is not valid", (
        f"expected the rejection to name the invalid feature, got {message!r}"
    )

    # positive control: the identical call against a real, known feature succeeds and the new
    # value round-trips through an independent read (GetMetadata)
    uib.put_metadata_flag(
        appId=app_id,
        environmentName=_ENV,
        featureName=_VALID_FEATURE,
        body={"newValue": "false"},
    )
    features = uib.get_metadata(appId=app_id, environmentName=_ENV)["features"]
    assert features[_VALID_FEATURE] == "false", (
        f"expected {_VALID_FEATURE}='false' after PutMetadataFlag, got {features.get(_VALID_FEATURE)!r}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real": "true"})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
