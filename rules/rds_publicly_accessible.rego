package rules.rds_publicly_accessible

__rego__metadoc__ := {
   "custom": {
    "controls": {
      "RelationalDB": [
        "RelationalDB_E"
      ]
    },
    "severity": "High"
  },
  "description": "RDS instance 'Publicly Accessible' should not be enabled. Publicly accessible RDS instances allow any AWS user or anonymous user access to the data in the database. RDS instances should not be publicly accessible.",
  "id": "FG_R00278",
  "title": "RDS instance 'Publicly Accessible' should not be enabled"
}

input_type = "tf"

resource_type = "aws_db_instance"

default allow = false

allow {
  input.publicly_accessible == false
}
