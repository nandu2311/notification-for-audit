# Create a CloudWatch metric filter to match processing failure events
resource "aws_cloudwatch_log_metric_filter" "processing_failure_filter" {
  name           = "processing-failure-filter"
  /* count = length(var.au_05_pattern) */
  /* pattern        = "\"ERROR\" || \"Exception\" || \"Failure\" || \"Critical\" || \"Timeout\" || \"Invalid\" || \"Unavailable\" || \"Aborted\"" */
  pattern = "{($.errorMessage = \"ERROR\" ) || ($.errorMessage = \"Exception\") || ($.errorMessage = \"Failure\" ) || ($.errorMessage = \"Critical\") || ($.errorMessage = \"Timeout\") || ($.errorMessage = \"Invalid\") || ($.errorMessage = \"Unavailable\") || ($.errorMessage = \"Invalid\" )}"
  /* pattern = "($.errorMessage = \"ERROR\" )" */
  log_group_name = aws_cloudwatch_log_group.audit-logs.name
  metric_transformation {
    name      = "ProcessingFailureMetric"
    namespace = var.namespace
    value     = "1"
  }
}

# Create a CloudWatch Alarm to trigger the SNS topic for processing failure events
resource "aws_cloudwatch_metric_alarm" "processing_failure_alarm" {
  alarm_name          = "processing-failure-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ProcessingFailureMetric"
  namespace           = var.namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  datapoints_to_alarm = 1
  alarm_description   = "Processing failure alarm"
  alarm_actions       = [aws_sns_topic.au-05-msg-topic.arn]
  insufficient_data_actions = []

}

