variable "regions" {
  type        = string
  description = "Enter the region in this format '<countrycode>-<direction>-<1or2or3>'"
}

variable "managedpolicyarns" {
  type = list(string)
  default = [
    "arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonSNSReadOnlyAccess",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
  ]
}


variable "patchgroupinput" {
  type        = string
  description = "Enter the patch group value. The values are Production, Non-Production and Pre-Production. Input is Case Sensitive."
}

variable "inspectorassessmentname" {
  type        = string
  description = "Enter the Inspector Assessment Template name"
}

variable "assessmentduration" {
  type        = number
  description = <<EOF
  Enter the duration (in seconds) for the assessment run. Minimum 180 seconds (3 mins), maximum 86400 seconds (24 hrs).
  Recommended is 3600 seconds (1 hr). Enter a value between 180 and 86400.
  EOF
  default     = 900
}

variable "rulespackage" {
  type = map
  default = {

    us-east-1 = {

      CVERules              = "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7"
      CISRules              = "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8"
      NetworkReachability   = "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd"
      SecurityBestPractices = "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q"
      ServiceAccountArn     = "arn:aws:iam::316112463485:root"

    }

    us-east-2 = {

      CVERules              = "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-JnA8Zp85"
      CISRules              = "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-m8r61nnh"
      NetworkReachability   = "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-cE4kTR30"
      SecurityBestPractices = "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-AxKmMHPX"
      ServiceAccountArn     = "arn:aws:iam::646659390643:root"

    }

    us-west-1 = {

      CVERules              = "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa"
      CISRules              = "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX"
      NetworkReachability   = "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF"
      SecurityBestPractices = "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm"
      ServiceAccountArn     = "arn:aws:iam::166987590008:root"

    }

    us-west-2 = {

      CVERules              = "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p"
      CISRules              = "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc"
      NetworkReachability   = "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl"
      SecurityBestPractices = "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ"
      ServiceAccountArn     = "arn:aws:iam::758058086616:root"

    }

    ap-south-1 = {

      CVERules              = "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO"
      CISRules              = "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-PSUlX14m"
      NetworkReachability   = "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-YxKfjFu1"
      SecurityBestPractices = "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-fs0IZZBj"
      ServiceAccountArn     = "arn:aws:iam::162588757376:root"

    }

    ap-southeast-1 = {

      CVERules              = "NotSupported"
      CISRules              = "NotSupported"
      SecurityBestPractices = "NotSupported"
      NetworkReachability   = "NotSupported"
      ServiceAccountArn     = "NotSupported"

    }

    ap-southeast-2 = {

      CVERules              = "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-D5TGAxiR"
      CISRules              = "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-Vkd2Vxjq"
      NetworkReachability   = "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-FLcuV4Gz"
      SecurityBestPractices = "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-asL6HRgN"
      ServiceAccountArn     = "arn:aws:iam::454640832652:root"

    }

    ap-northeast-1 = {

      CVERules              = "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-gHP9oWNT"
      CISRules              = "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-7WNjqgGu"
      NetworkReachability   = "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-YI95DVd7"
      SecurityBestPractices = "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-bBUQnxMq"
      ServiceAccountArn     = "arn:aws:iam::406045910587:root"

    }

    ap-northeast-2 = {

      CVERules              = "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoGHMznc"
      CISRules              = "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-T9srhg1z"
      NetworkReachability   = "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-s3OmLzhL"
      SecurityBestPractices = "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-2WRpmi4n"
      ServiceAccountArn     = "arn:aws:iam::526946625049:root"

    }

    eu-central-1 = {

      CVERules              = "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-wNqHa8M9"
      CISRules              = "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-nZrAVuv8"
      NetworkReachability   = "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-6yunpJ91"
      SecurityBestPractices = "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-ZujVHEPB"
      ServiceAccountArn     = "arn:aws:iam::537503971621:root"

    }

    eu-west-1 = {

      CVERules              = "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh"
      CISRules              = "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F"
      NetworkReachability   = "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe"
      SecurityBestPractices = "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6"
      ServiceAccountArn     = "arn:aws:iam::357557129151:root"

    }

    eu-west-2 = {

      CVERules              = "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-kZGCqcE1"
      CISRules              = "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-IeCjwf1W"
      NetworkReachability   = "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-AizSYyNq"
      SecurityBestPractices = "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-XApUiSaP"

    }


    eu-west-3 = {

      CVERules              = "NotSupported"
      CISRules              = "NotSupported"
      SecurityBestPractices = "NotSupported"
      NetworkReachability   = "NotSupported"

    }

    eu-north-1 = {

      CVERules              = "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-IgdgIewd"
      CISRules              = "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-Yn8jlX7f"
      NetworkReachability   = "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-52Sn74uu"
      SecurityBestPractices = "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-HfBQSbSf"
      ServiceAccountArn     = "arn:aws:iam::453420244670:root"

    }

    ca-central-1 = {

      CVERules              = "NotSupported"
      CISRules              = "NotSupported"
      SecurityBestPractices = "NotSupported"
      NetworkReachability   = "NotSupported"
      ServiceAccountArn     = "NotSupported"

    }

    sa-east-1 = {

      CVERules              = "NotSupported"
      CISRules              = "NotSupported"
      SecurityBestPractices = "NotSupported"
      NetworkReachability   = "NotSupported"
      ServiceAccountArn     = "NotSupported"

    }


    us-gov-east-1 = {

      CVERules              = "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-3IFKFuOb"
      CISRules              = "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-pTLCdIww"
      NetworkReachability   = "NotSupported"
      SecurityBestPractices = "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-vlgEGcVD"
      ServiceAccountArn     = "arn:aws-us-gov:iam::206278770380:root"
    }

    us-gov-west-1 = {

      CVERules              = "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-4oQgcI4G"
      CISRules              = "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-Ac4CFOuc"
      NetworkReachability   = "NotSupported"
      SecurityBestPractices = "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-rOTGqe5G"
      ServiceAccountArn     = "arn:aws-us-gov:iam::850862329162:root"

    }
  }
}

variable "rulepackageselection" {
  type        = string
  description = <<EOF
    Select the rule packages needed for the Inspector Assessment run. Add a comma after each selection.
    Available rule packages are - CVERules, CISRules, NetworkReachability, SecurityBestPractices. (Maintain the Order)
    If you want to specify only specific rules, use the pattern below.
    "X, X, NetworkReachability, SecurityBestPractices"
    EOF
}

variable "rulepackagedefault" {
  type    = list(string)
  default = ["CVERules", "CISRules", "NetworkReachability", "SecurityBestPractices"]
}

variable "needitsm" {
  type        = string
  description = "Enter Yes if you want to send the Inspector findings to an ITSM Tool. No if not. CASE SENSITIVE"
}

variable "protocolforitsm" {
  type        = string
  description = "Enter the protocol for sending data to ITSM tool. Allowed Values are HTTP, HTTPS, Email. If you have selected 'No' for Need ITSM. Press enter"
}

variable "endpointforitsm" {
  type        = string
  description = "Enter the endpoint for the ITSM Tool. If you have selected 'No' for Need ITSM. Press enter"
}

variable "sendermailID" {
  type        = string
  description = "Enter email that will be used as sender of the Vulnerability Reports to respective stakeholders."
}

variable "receivermailID" {
  type        = string
  description = "Enter email(s) that are used to receive Vulnerability Reports. For multiple receivers enter a forward slash (/) in between."
}

variable "bucketname" {
  type        = string
  description = "Enter the S3 Bucket in which the Python Packages zip file is located."
}