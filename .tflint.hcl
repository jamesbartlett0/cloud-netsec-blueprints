plugin "aws" {
enabled = true
version = "0.32.0"
source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

plugin "azure" {
enabled = true
version = "0.25.1"
source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

rule "terraform_naming_convention" {
enabled = true
}