resource "aws_cloudwatch_log_metric_filter" "console-login-failure" {
  name           = "ConsoleLoginFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "ConsoleSigninFailureCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console-failure-alarm" {
  alarm_name                = "Console sign-in failures"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "ConsoleSigninFailureCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 3
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors console login failure"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
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
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console-success-alarm" {
  alarm_name                = "Console sign-in Success"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "ConsoleSigninSuccessCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors console login Success"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
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
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam-authentication-alarm" {
  alarm_name                = "IAMAuthnAuthzActivityAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "IAMAuthnAuthzActivity"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors IAM Authentication and Authorization Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
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
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam-policy-alarm" {
  alarm_name                = "IAM Policy Changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "IAMPolicyEventCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors IAM Policy Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
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
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security-group-alarm" {
  alarm_name                = "SecurityGroup Configuration changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "SecurityGroupEventCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors Security Group configuration changes Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
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
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ec2-alarm" {
  alarm_name                = "EC2 status Changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "EC2ActivityCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  datapoints_to_alarm       = 1
  alarm_description         = "This metric monitors Security Group configuration changes Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized-api-metric" {
  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized-api-alarm" {
  alarm_name                = "UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 1
  metric_name               = "UnauthorizedAPICalls"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 3
  datapoints_to_alarm       = 1
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
}