data "aws_caller_identity" "current" {}

variable "region" {
  type = string
  default = "ap-south-1"
}


resource "aws_cloudtrail" "audit-trail" {
  name                          = "audit-data"
  s3_bucket_name                = aws_s3_bucket.audit-bucket.bucket
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true


  # sendint events to Cloudwatch logs group 
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.audit-logs.arn}:*"

}

resource "aws_s3_bucket" "audit-bucket" {
  bucket        = "audit-data-for-sns"
  force_destroy = true

}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name               = "ctw_cloudwatch_roles"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
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
    resources = ["${aws_s3_bucket.audit-bucket.arn}/AWSLogs/*"]

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
  description = "Allows CloudTrail to write logs to the specified CloudWatch Logs log group"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailCreateLogStream2014110",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.audit-logs.id}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_ap-south-1*"
            ]
        },
        {
            "Sid": "AWSCloudTrailPutLogEvents20141101",
            "Effect": "Allow",
            "Action": [
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.audit-logs.id}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_ap-south-1*"
            ]
        }
    ]
}
EOF

}

/* aws_cloudwatch_log_stream.audit-stream.arn */
/* aws_cloudwatch_log_group.audit-logs.arn */

resource "aws_iam_role_policy_attachment" "cloudtrail_cwl_logs_policy_attachment" {
  policy_arn = aws_iam_policy.cloudtrail_cwl_logs_policy.arn
  role       = aws_iam_role.cloudtrail_cloudwatch_role.name
}

resource "aws_iam_role_policy_attachment" "cloudtrail_full-access" {
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess"
  role       = aws_iam_role.cloudtrail_cloudwatch_role.name
}


output "values-for-resources" {
  value = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.audit-logs.id}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_ap-south-1*"
}