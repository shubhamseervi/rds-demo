package rules.rds_supported_engine

__rego__metadoc__ := {
  "custom": {
    "controls": {
      "RelationalDB": [
        "RelationalDB_D"
      ]
    },
    "severity": "Low"
  },
  "description": "RDS instances should have FedRAMP approved database engines. FedRAMP-approved database engines such as MySQL and PostgresQL satisfy strict U.S. government requirements for securing sensitive data. An RDS instance should use an approved database engine.",
  "id": "FG_R00094",
  "title": "RDS instances should have FedRAMP approved database engines"
}

input_type = "tf"

resource_type = "aws_db_instance"

default allow = false

allow {
  input.engine == "postgres"
}
