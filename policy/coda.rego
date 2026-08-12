package coda.authz

default decision := {
    "allow": false,
    "required_permission": ""
}

decision := {
    "allow": true,
    "required_permission": "diagnostics:read"
} if {
    input.relying_domain == "vendor-b"
    input.action == "read"

    startswith(input.resource, "/assets/")
    endswith(input.resource, "/diagnostics")

    input.context.purpose == "predictive-maintenance"
    input.context.plant == "factory-a"

    "diagnostics:read" in input.effective_scope
}
