package rules.rds_input.auto_minor_version_upgrade

__rego__metadoc__ := {
  "custom": {
    "controls": {
      "AWSDBBENCH2": [
        "AWSDBBENCH2_N"
      ]
    },
    "severity": "Medium"
  },
  "description": "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances BAI10.05.04",
  "id": "BAI10.05.04",
  "title": "Auto Minor Version Upgrade feature Enabled for RDS Instances"
}

input_type = "tf"

resource_type = "aws_db_instance"

default allow = false

allow {
  input.auto_minor_version_upgrade == true
}
