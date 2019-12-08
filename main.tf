provider "aws" {
  region = var.regions
}


# -------------------------------- IAM Resources ------------------------------

# IAM Role for Lambda
resource "aws_iam_role" "LambdaRole" {
  name               = "LambdaRoleforVulnerabilitySolution"
  description        = "A role for Lambda to access the required services for the solution"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Effect": "Allow"
        }
    ]
}
EOF

}

#Attach Multiple Policies for a role
resource "aws_iam_role_policy_attachment" "LambdaRolePolicyAttachment" {
  role       = aws_iam_role.LambdaRole.name
  count      = length(var.managedpolicyarns)
  policy_arn = var.managedpolicyarns[count.index]
}

# Add a custom policy for LambdaRole
resource "aws_iam_role_policy" "LambdaRolePolicy" {
  name = "LambdaRoleCustomPolicy"
  role = aws_iam_role.LambdaRole.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail",
                "sns:Publish"
            ],
            "Resource": "*"
        }
    ]
}
EOF

}

# Inspector Notification Topic Policy
resource "aws_sns_topic_policy" "InspectorNotificationTopicPolicy" {
  arn    = aws_sns_topic.InspectorNotificationTopic.arn
  policy = data.aws_iam_policy_document.InspectorNotificationTopicPolicyDocument.json
}

data "aws_iam_policy_document" "InspectorNotificationTopicPolicyDocument" {
  statement {
    actions = ["sns:Publish"]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [var.rulespackage[var.regions]["ServiceAccountArn"]]
    }

    resources = [aws_sns_topic.InspectorNotificationTopic.arn]
  }
}

# SNS Lambda Trigger

resource "aws_lambda_permission" "SNSLambdaTrigger" {
  function_name = aws_lambda_function.VulnerabilitiesReportingFunction.function_name
  principal     = "lambda.amazonaws.com"
  action        = "lambda:InvokeFunction"
  source_arn    = aws_sns_topic.InspectorNotificationTopic.arn

}


# ------------------------- END of IAM Section ---------------------

# ------------------------- Inspector Resources -----------------------

# Inspector Resource Group
resource "aws_inspector_resource_group" "InspectorResourceGroup" {
  tags = {
    "Patch Group1" : contains(split(",", var.patchgroupinput), "Production") ? "Production" : "AWS::NoValue"
    "Patch Group2" : contains(split(",", var.patchgroupinput), " Non-Production") ? "Non-Production" : "AWS::NoValue"
    "Patch Group3" : contains(split(",", var.patchgroupinput), " Pre-Production") ? "Pre-Production" : "AWS::NoValue"
  }
}

# Inspector Assessment Targets
resource "aws_inspector_assessment_target" "InspectorAssessmentTarget" {
  name               = "InspectorAssessmentTarget"
  resource_group_arn = aws_inspector_resource_group.InspectorResourceGroup.arn
}

# Inspector Assessment Template

resource "aws_inspector_assessment_template" "InspectorAssessmentRun" {
  name       = var.inspectorassessmentname
  target_arn = aws_inspector_assessment_target.InspectorAssessmentTarget.arn
  duration   = var.assessmentduration
  rules_package_arns = [
    contains(split(",", var.rulepackageselection), "CVERules") ? var.rulespackage[var.regions]["CVERules"] : "",
    contains(split(",", var.rulepackageselection), " CISRules") ? var.rulespackage[var.regions]["CISRules"] : "",
    contains(split(",", var.rulepackageselection), " NetworkReachability") ? var.rulespackage[var.regions]["NetworkReachability"] : "",
  contains(split(",", var.rulepackageselection), " SecurityBestPractices") ? var.rulespackage[var.regions]["SecurityBestPractices"] : ""]
}

# --------------------------- END Of INSPECTOR Section ---------------------------------

# --------------------------- SNS Section -------------------------------

# SNS topic to link Inspector - Lambda - SNS [Main Artery]
resource "aws_sns_topic" "InspectorNotificationTopic" {
  name         = "Inspector-SNS-Lambda-Link"
  display_name = "Inspector-SNS-Lambda-Link"
}

resource "aws_sns_topic_subscription" "InspectorNotificationTopicSubscription" {
  topic_arn = aws_sns_topic.InspectorNotificationTopic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.VulnerabilitiesReportingFunction.arn
}

# SNS Topic for sending inspector data to ITSM tool
resource "aws_sns_topic" "InspectorFindingstoITSM" {
  name         = "Inspector-Findings-To-ITSM-Tool"
  display_name = "Inspector-Findings-To-ITSM-Tool"
  count        = var.needitsm == "Yes" ? 1 : 0
}

resource "aws_sns_topic_subscription" "InspectorFindingstoITSMSubscription" {
  topic_arn = aws_sns_topic.InspectorFindingstoITSM[count.index]
  protocol  = var.protocolforitsm
  endpoint  = var.endpointforitsm
  count     = var.needitsm == "Yes" ? 1 : 0
}

# -------------------------- END Of SNS Section -----------------------------

# -------------------------- Lambda Section ---------------------------------

resource "aws_lambda_function" "VulnerabilitiesReportingFunction" {
  function_name = "VulnerabilitiesReportingLambdaFunction"
  description   = "This lambda function gets the Inspector Findings, processess it and send a report to respective stakeholders."
  handler       = "lambda_function.lambda_handler"
  memory_size   = 512
  role          = aws_iam_role.LambdaRole.arn
  runtime       = "python3.6"
  timeout       = 900
  environment {
    variables = {
      "SES_FROM" : var.sendermailID
      "SES_TO" : var.receivermailID
    }
  }
  s3_bucket = var.bucketname
  s3_key    = "packages.zip"
}

resource "aws_lambda_function" "SinglePackageRemediation" {
  function_name = "SinglePackageRemediationFunction"
  description   = "This function will remediate packages that are specified."
  handler       = "Linux-SinglePackageRemediation.lambda_handler"
  memory_size   = 512
  role          = aws_iam_role.LambdaRole.arn
  runtime       = "python3.6"
  timeout       = 900
  s3_bucket     = var.bucketname
  s3_key        = "remediation_single.zip"
}

resource "aws_lambda_function" "AllPackageRemediation" {
  function_name = "AllPackageRemediationFunctionUbuntuAmznL1L2"
  description   = "This function will remediate packages that are specified. Only available for Ubuntu, Amazon Linux, Amazon Linux 2."
  handler       = "Linux-AllPackageRemediation.lambda_handler"
  memory_size   = 512
  role          = aws_iam_role.LambdaRole.arn
  runtime       = "python3.6"
  timeout       = 900
  s3_bucket     = var.bucketname
  s3_key        = "remediation_all.zip"
}