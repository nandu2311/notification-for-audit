resource "aws_sns_topic" "send-msg-topic" {
  name         = "Audit-SNS"
  display_name = "Audit-AU-Notification"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.send-msg-topic.arn
  protocol  = "email"
  endpoint  = "nandkishor.sr91@gmail.com"
}
