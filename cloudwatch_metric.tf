variable "namespace" {
  type = string
  default = "CloudtrailMetrics"
}

resource "aws_cloudwatch_log_metric_filter" "console-login-failure" {
  name           = "ConsoleLoginFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "ConsoleSigninFailureCount"
    namespace = var.namespace
    value     = "1"
  }
}

/* # Define the CloudWatch Logs group as a data source
data "aws_cloudwatch_log_group" "existing_logs_group" {
  name = "/aws/lambda/my-existing-logs-group"
} */

resource "aws_cloudwatch_metric_alarm" "console-failure-alarm" {
  alarm_name                = "Console sign-in failures"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "ConsoleSigninFailureCount"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 3
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors console login failure"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

## Console Login Successful notification

resource "aws_cloudwatch_log_metric_filter" "console-login-success" {
  name           = "ConsoleLoginSuccess"
  pattern        = "{ ($.eventName = ConsoleLogin) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "ConsoleSigninSuccessCount"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console-success-alarm" {
  alarm_name                = "Console sign-in Success"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "ConsoleSigninSuccessCount"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors console login Success"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

# IAM Authentication and authorization Changes notification
resource "aws_cloudwatch_log_metric_filter" "iam-authentication-activity" {
  name           = "IAMAuthnAuthzActivity"
  pattern        = "{ ( ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"Put*Policy\") || ($.eventName = \"Attach*\") || ($.eventName = \"Detach*\") || ($.eventName = \"Create*\") || ($.eventName = \"Update*\") || ($.eventName = \"Upload*\") || ($.eventName = \"Delete*\") || ($.eventName = \"Remove*\") || ($.eventName = \"Set*\")) ) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "IAMAuthnAuthzActivity"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam-authentication-alarm" {
  alarm_name                = "IAMAuthnAuthzActivityAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "IAMAuthnAuthzActivity"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors IAM Authentication and Authorization Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

#IAM Policy Changes Notification
resource "aws_cloudwatch_log_metric_filter" "iam-policy-activity" {
  name           = "IAMPolicyChanges"
  pattern        = "{($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\")}"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "IAMPolicyEventCount"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam-policy-alarm" {
  alarm_name                = "IAM Policy Changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "IAMPolicyEventCount"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors IAM Policy Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

## SecurityGroup Event Activity
resource "aws_cloudwatch_log_metric_filter" "security-group-activity" {
  name           = "SecurityGroupEvent"
  pattern        = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "SecurityGroupEventCount"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security-group-alarm" {
  alarm_name                = "SecurityGroup Configuration changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "SecurityGroupEventCount"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors Security Group configuration changes Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

## EC2 Activity
## SecurityGroup Event Activity
resource "aws_cloudwatch_log_metric_filter" "ec2-activity" {
  name           = " Ec2Activity"
  pattern        = "{ ($.eventName = \"RunInstances\") || ($.eventName = \"StopInstances\") || ($.eventName = \"TerminateInstances\") || ($.eventName = \"Reboot\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "EC2ActivityCount"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2-alarm" {
  alarm_name                = "EC2 status Changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "EC2ActivityCount"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors Security Group configuration changes Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized-api-metric" {
  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized-api-alarm" {
  alarm_name                = "UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "UnauthorizedAPICalls"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 3
  datapoints_to_alarm       = 1
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

# Root Access Usage
resource "aws_cloudwatch_log_metric_filter" "root_usage-metric" {
  name           = "RootUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "RootUsage"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage-alarm" {
  alarm_name                = "RootUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "RootUsage"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

## Cloudtrail Configuration Changes
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg_changes" {
  name           = "CloudTrailCfgChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "CloudTrailCfgChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  alarm_name                = "CloudTrailCfgChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "CloudTrailCfgChanges"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

resource "aws_cloudwatch_log_metric_filter" "disable_or_delete_cmk" {
  name           = "DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "DisableOrDeleteCMK"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "disable_or_delete_cmk" {
  alarm_name                = "DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "DisableOrDeleteCMK"
  namespace                 = var.namespace
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Data encrypted with disabled or deleted keys will no longer be accessible."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  name           = "S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  alarm_name                = "S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "S3BucketPolicyChanges"
  namespace                 = var.namespace
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  name           = "AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  alarm_name                = "AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "AWSConfigChanges"
  namespace                 = var.namespace
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  name           = "NACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "NACLChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  alarm_name                = "NACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "NACLChanges"
  namespace                 = var.namespace
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

resource "aws_cloudwatch_log_metric_filter" "network_gw_changes" {
  name           = "NetworkGWChanges"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "NetworkGWChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  alarm_name                = "NetworkGWChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "NetworkGWChanges"
  namespace                 = var.namespace
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  name           = "RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  alarm_name                = "RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "RouteTableChanges"
  namespace                 = var.namespace
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [aws_sns_topic.au-03-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

}

### Web Server Application Monitoring#####
# Create a CloudWatch Metric Filter
resource "aws_cloudwatch_log_metric_filter" "webapplication_failure_filter" {
  name           = "processing-failure-filter"
  /* pattern        = "[$.EventName, $.EventMessage] = /(?i)(${join("|", [
    "Application Error",
    "ASP.NET Unhandled Exception",
    ".NET Runtime Error",
    "Service Unexpectedly Terminated",
    "Service Terminated Unexpectedly",
    "Application Pool Failure",
    "Failed Login Attempt",
    "Object Operation Failed",
    "Application Pool Disabled",
    "Internal Server Error",
    "Service Unavailable"
  ])})/" */
  count          = length(var.webapp_logs)
  pattern        = "[$.EventName, $.EventMessage] = /${var.webapp_logs[count.index]}/"
  ##Change the log group name here for webapp logs
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  
  metric_transformation {
    name          = "WebAppFailureCount"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
}

/* output "testing-pattern" {
  value = aws_cloudwatch_metric_filter.webapplication_failure_filter.pattern
} */

# Create a CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "webapplication_failure_alarm" {
  count               = length(var.webapp_logs)
  alarm_name          = "${var.webapp_logs[count.index]}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "WebAppFailureCount"
  namespace           = var.namespace
  period              = "60"
  statistic           = "SampleCount"
  threshold           = 1
  alarm_description = "Processing failure alarm for IIS web application"
  alarm_actions     = [aws_sns_topic.au-03-msg-topic.arn]
  datapoints_to_alarm = 1
  treat_missing_data = "notBreaching"
  insufficient_data_actions = []

  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.audit-logs.name
  }
}
