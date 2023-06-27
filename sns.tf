resource "aws_sns_topic" "au-03-msg-topic" {
  name         = "Audit-AU-03"
  display_name = "Audit-AU-03-Notification"
}

resource "aws_sns_topic_subscription" "au-03_subscription" {
  topic_arn = aws_sns_topic.au-03-msg-topic.arn
  protocol  = "email"
  endpoint  = "nandkishor.sr91@gmail.com"
}

resource "aws_sns_topic" "au-05-msg-topic" {
  name         = "Audit-AU-05"
  display_name = "Audit-AU-05-Notification"
}

resource "aws_sns_topic_subscription" "au-05_subscription" {
  topic_arn = aws_sns_topic.au-05-msg-topic.arn
  protocol  = "email"
  endpoint  = "nandkishor.sr91@gmail.com"
}

resource "aws_sns_topic" "au-07-msg-topic" {
  name         = "Audit-AU-07"
  display_name = "Audit-AU-07-Notification"
}

resource "aws_sns_topic_subscription" "au-07_subscription" {
  topic_arn = aws_sns_topic.au-07-msg-topic.arn
  protocol  = "email"
  endpoint  = "nandkishor.sr91@gmail.com"
}