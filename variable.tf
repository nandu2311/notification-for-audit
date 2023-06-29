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

variable "au_05_pattern" {
    description = "pattern for au-05 processing failure events"
    default = ["ERROR","Exception","Failure","Critical","Timeout","Invalid","Unavailable","Aborted"]
    type = list(any)
}


