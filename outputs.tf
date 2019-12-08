output "PatchGroup" {
  value = var.patchgroupinput
}

output "AssessmentName" {
  value = var.inspectorassessmentname
}

output "Duration" {
  value = var.assessmentduration
}

output "RulePackages" {
  value = var.rulepackageselection
}

output "ITSMRequirement" {
  value = var.needitsm
}

output "ITSMProtocol" {
  value = var.protocolforitsm
}

output "ITSMEndpoint" {
  value = var.endpointforitsm
}

output "SenderMailID" {
  value = var.sendermailID
}

output "Receiver" {
  value = var.receivermailID
}

output "S3Bucket" {
  value = var.bucketname
}
