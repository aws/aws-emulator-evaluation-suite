"""update-configuration-profile-modifies-validators-and-persists."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-configuration-profile-modifies-validators-and-persists"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-configuration-profile-validators"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationProfile persists Validators/Description changes, via GetConfigurationProfile.

    LocationUri is immutable after creation (UpdateConfigurationProfile does not accept it),
    so this also asserts it stays unchanged across the update.
    """
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    initial_uri = f"codepipeline://{ctx.unique_name('sim2real-pipeline-')}"
    created = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri=initial_uri,
        Type="AWS.Freeform",
        Tags=_TAGS,
    )
    profile_id = created["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    assert created["LocationUri"] == initial_uri, f"expected LocationUri {initial_uri!r}, got {created['LocationUri']!r}"
    assert created.get("Validators", []) == [], f"expected no Validators on a fresh profile, got {created.get('Validators')!r}"

    schema = json.dumps({"$schema": "http://json-schema.org/draft-04/schema#", "type": "object"})
    updated = appconfig.update_configuration_profile(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Description="now schema-validated",
        Validators=[{"Type": "JSON_SCHEMA", "Content": schema}],
    )
    assert updated["LocationUri"] == initial_uri, "LocationUri is immutable and must be unchanged by update"
    assert updated["Description"] == "now schema-validated", f"expected updated Description, got {updated['Description']!r}"
    assert len(updated["Validators"]) == 1, f"expected exactly 1 Validator on the update response, got {len(updated['Validators'])}"
    assert updated["Validators"][0]["Type"] == "JSON_SCHEMA", f"expected JSON_SCHEMA validator type, got {updated['Validators'][0]['Type']!r}"
    assert updated["Validators"][0]["Content"] == schema, "update response Validator Content must echo what was sent"

    got = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    assert got["LocationUri"] == initial_uri, "LocationUri must remain unchanged after update"
    assert got["Description"] == "now schema-validated", f"expected persisted Description, got {got['Description']!r}"
    assert len(got["Validators"]) == 1, f"expected exactly 1 persisted Validator, got {len(got['Validators'])}"
    assert got["Validators"][0]["Type"] == "JSON_SCHEMA", f"expected persisted JSON_SCHEMA validator, got {got['Validators'][0]['Type']!r}"
    assert got["Validators"][0]["Content"] == schema, "independent read must return the persisted Validator Content"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

