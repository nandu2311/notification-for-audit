
## Create Cloudwatch EventBus 
/* resource "aws_cloudwatch_event_bus" "audit-bus" {
  name = "audit-event-bus"
} */

## eventbus policy
/* data "aws_iam_policy_document" "audit-eventbus-policy" {
  statement {
    sid    = "DevAccountAccess"
    effect = "Allow"
    actions = [
      "events:PutEvents",
    ]
    resources = [
      aws_cloudwatch_event_bus.audit-bus.arn
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "audit-bus-policy-attachment" {
  policy         = data.aws_iam_policy_document.audit-eventbus-policy.json
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name
} */

### Create Event Rules 

# 1) Console login notification
/* resource "aws_cloudwatch_event_rule" "console-login" {
  name           = "aws_sign_in"
  description    = "capture each AWS console Sign In"
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name

  event_pattern = <<EOF
    {
      "detail-type": [
        "AWS Console Sign In via CloudTrail"
      ]
    }
EOF
}

resource "aws_cloudwatch_event_target" "console-attach-sns" {
  rule = aws_cloudwatch_event_rule.console-login.name
  arn            = aws_sns_topic.send-msg-topic.arn
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name


}

resource "aws_cloudwatch_event_target" "console-login-sns" {
  arn            = aws_sns_topic.send-msg-topic.arn
  rule           = aws_cloudwatch_event_rule.console-login.name
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name

  input_transformer {
    input_paths = {
      region = "$.detail.awsRegion",
      user   = "$.detail.userIdentity.arn"
      source = "$.detail.eventSource",
      time   = "$.time",
      event  = "$.detail.eventName",

    }
    input_template = "\"Notification Console Login In your AWS Account '<user>' in the region '<region>' at the time '<time>' the following took place: <event> and <source> \""
  }
} */

### EC2 Instance state change notification
resource "aws_cloudwatch_event_rule" "ec2-status-changes" {
  name        = "ec2-status-change"
  description = "Capture each Instance state like Stop, Start, Terminate"
  /* event_bus_name = aws_cloudwatch_event_bus.audit-bus.name */

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification"]
    detail = {
      state = ["terminated", "stopped", "running"]
    }
  })
}

resource "aws_cloudwatch_event_target" "ec2-status-sns" {
  arn  = aws_sns_topic.au-03-msg-topic.arn
  rule = aws_cloudwatch_event_rule.ec2-status-changes.name
/* event_bus_name = aws_cloudwatch_event_bus.audit-bus.name */

input_transformer {
    input_paths = {
      instance  = "$.detail.requestParameters.instancesSet.items",
      status    = "$.detail.status",
      useragent = "$.detail.userAgent",
      source    = "$.detail.eventSource",
      time      = "$.time",
      event     = "$.detail.eventName",
      region    = "$.detail.awsRegion",
      user      = "$.detail.userIdentity.arn"

    }
    input_template = "\"In your AWS Account '<user>' in the region '<region>' at the time '<time>' the following took place: <event> of this instance <instance> and source of <source>.\""
  }
}

### Route53 change notification
resource "aws_cloudwatch_event_rule" "r53-status-changes" {
  name        = "Route53Activity"
  description = "Route53 configuration changes"
  /* event_bus_name = aws_cloudwatch_event_bus.audit-bus.name */

  event_pattern = jsonencode({
    source      = ["aws.route53"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["route53.amazonaws.com"]
    }
  })
}


resource "aws_cloudwatch_event_target" "r53-status-sns" {
  arn  = aws_sns_topic.au-03-msg-topic.arn
  rule = aws_cloudwatch_event_rule.r53-status-changes.name
/* event_bus_name = aws_cloudwatch_event_bus.audit-bus.name */

input_transformer {
    input_paths = {
      instance  = "$.detail.requestParameters.instancesSet.items",
      status    = "$.detail.status",
      useragent = "$.detail.userAgent",
      source    = "$.detail.eventSource",
      time      = "$.time",
      event     = "$.detail.eventName",
      region    = "$.detail.awsRegion",
      user      = "$.detail.userIdentity.arn"

    }
    input_template = "\"In your AWS Account '<user>' in the region '<region>' at the time '<time>' the following took place: <event> & <source>.\""
  }
}

## S3 Activity on Bucket and all objects
/* resource "aws_cloudwatch_event_rule" "s3_activity" {
  name           = "s3-activity"
  description    = "capture each state of bucket activity like listbucket, createbucket, deletebucket"
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name

  event_pattern = jsonencode({
    source = [
      "aws.s3"
    ]
  })
} */

/* resource "aws_cloudwatch_event_target" "s3-attach-sns" {
  rule      = aws_cloudwatch_event_rule.console-login.name
  arn       = aws_sns_topic.send-msg-topic.arn
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name

}

resource "aws_sns_topic_policy" "sns-policy-attachment" {
  arn    = aws_sns_topic.send-msg-topic.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}


data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.send-msg-topic.arn]
  }
}

resource "aws_cloudwatch_event_target" "s3-activity-sns" {
  arn  = aws_sns_topic.send-msg-topic.arn
  rule = aws_cloudwatch_event_rule.s3_activity.name
  event_bus_name = aws_cloudwatch_event_bus.audit-bus.name

  input_transformer {
    input_paths = {
      s3_activity    = "$.detail.eventName",
      source         = "$.detail.eventSource",
      time           = "$.detail.eventTime",
      region         = "$.detail.awsRegion",
      user           = "$.detail.userIdentity.arn",
      s3_bucket_name = "$.detail.requestParameters.bucketName"
    }
    input_template = "\"A <s3_activity> for <s3_bucket_name> API Call was made against the S3 Bucket with the following details 'Region' - <region>, 'Source' - <source>, 'Bucket Activity' - <s3_activity>, 'EventTime' - <time>, 'User' - <user>\""

  }
} */
