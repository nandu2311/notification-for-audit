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
  evaluation_periods        = 2
  metric_name               = "ConsoleSigninFailureCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 3
  alarm_description         = "This metric monitors console login failure"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  insufficient_data_actions = []
}

## Console Login Successful notification

resource "aws_cloudwatch_log_metric_filter" "console-login-success" {
  name           = "ConsoleLoginSuccess"
  pattern = "{ ($.eventName = ConsoleLogin) }"
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
  evaluation_periods        = 2
  metric_name               = "ConsoleSigninSuccessCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "This metric monitors console login Success"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  insufficient_data_actions = []
}

# IAM Authentication Changes notification
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
  evaluation_periods        = 2
  metric_name               = "IAMAuthnAuthzActivity"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "This metric monitors IAM Authentication and Authorization Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  insufficient_data_actions = []
}

#IAM Policy Changes Notification
resource "aws_cloudwatch_log_metric_filter" "iam-policy-activity" {
  name           = "IAMPolicyChanges"
  /* pattern        = "{($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\")} }" */
  pattern = "{($.eventName = \"DeleteGroupPolicy|DeleteRolePolicy|DeleteUserPolicy|PutGroupPolicy|PutRolePolicy|PutUserPolicy|CreatePolicy|DeletePolicy|CreatePolicyVersion|DeletePolicyVersion|AttachRolePolicy|DetachRolePolicy|AttachUserPolicy|DetachUserPolicy|AttachGroupPolicy|DetachGroupPolicy\" )}"
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
  evaluation_periods        = 2
  metric_name               = "IAMPolicyEventCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "This metric monitors IAM Policy Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  insufficient_data_actions = []
}

## SecurityGroup Event Activity
resource "aws_cloudwatch_log_metric_filter" "security-group-activity" {
  name           = " SecurityGroupEvent"
  pattern        = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name

  metric_transformation {
    name      = " SecurityGroupEventCount"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security-group-alarm" {
  alarm_name                = "SecurityGroup Configuration changes"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = 2
  metric_name               = "SecurityGroupEventCount"
  namespace                 = "CloudTrailMetrics"
  period                    = 120
  statistic                 = "Sum"
  threshold                 = 1
  alarm_description         = "This metric monitors IAM Policy Activity"
  actions_enabled           = "true"
  alarm_actions             = [aws_sns_topic.send-msg-topic.arn]
  insufficient_data_actions = []
}