data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "audit-trail" {
  name                          = "audit-data"
  s3_bucket_name                = aws_s3_bucket.audit-bucket.id
  s3_key_prefix                 = "prefix"
  enable_logging                = true
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

  }

  # sendint events to Cloudwatch logs group 
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.audit-logs.arn}:*"

}

resource "aws_s3_bucket" "audit-bucket" {
  bucket        = "audit-data-for-sns"
  force_destroy = true

}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "ctw_cloudwatch_roles"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {
            "Service" : "cloudtrail.amazonaws.com"
          },
          "Action" : "sts:AssumeRole"
        }
      ]
  })


  depends_on = [
    aws_cloudwatch_log_group.audit-logs,
  ]
}

data "aws_iam_policy_document" "s3_bucket_policy" {

  version = "2012-10-17"

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit-bucket.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit-bucket.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

}


resource "aws_s3_bucket_policy" "audit-attach-policy" {
  bucket = aws_s3_bucket.audit-bucket.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}

resource "aws_cloudwatch_log_group" "audit-logs" {
  name = "audit-logs-sns"

}

resource "aws_cloudwatch_log_stream" "audit-stream" {
  name           = "audit-log-stream"
  log_group_name = aws_cloudwatch_log_group.audit-logs.name
}


resource "aws_iam_policy" "cloudtrail_cwl_logs_policy" {
  name        = "CloudTrail_CWL_Logs_Policy"
  path        = "/"
  description = "Allows CloudTrail to write logs to the specified CloudWatch Logs log group"

  /* policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:GetLogGroupFields",
          "logs:GetLogRecord",
          "logs:GetQueryResults"
        ]
        Resource = ["${aws_cloudwatch_log_stream.audit-stream.arn}*"]
      }
    ]
  }) */

  policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid = "AWSCloudTrailCreateLogStream2014110"
          Effect = "Allow"
          Action = [ "logs:CreateLogStream" ]
          Resource = [ "${aws_cloudwatch_log_stream.audit-stream.arn}:*" ]
        },
        {
          Sid = "AWSCloudTrailPutLogEvents20141101"
          Effect = "Allow"
          Action = [ "logs:PutLogEvents" ]
          Resource = [ "${aws_cloudwatch_log_stream.audit-stream.arn}:*" ]

        }
      ]
    })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_cwl_logs_policy_attachment" {
  policy_arn = aws_iam_policy.cloudtrail_cwl_logs_policy.arn
  role       = aws_iam_role.cloudtrail_cloudwatch_role.name
}

output "output-test-streamstar" {
  value = "${aws_cloudwatch_log_stream.audit-stream.arn}:*"
}

output "output-test-withoutstart" {
  value = aws_cloudwatch_log_stream.audit-stream.arn
}