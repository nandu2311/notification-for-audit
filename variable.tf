variable "webapp_logs" {
    description = "webapps logs list"
    default = ["Application Error",
    "ASP.NET Unhandled Exception",
    ".NET Runtime Error",
    "Service Unexpectedly Terminated",
    "Service Terminated Unexpectedly",
    "Application Pool Failure",
    "Failed Login Attempt",
    "Object Operation Failed",
    "Application Pool Disabled",
    "Internal Server Error",
    "Service Unavailable" ]
    type = list(any)
}



