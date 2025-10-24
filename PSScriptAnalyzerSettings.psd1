@{
	Rules        = @{
		PSUseDeclaredVarsMoreThanAssignments = @{
			Enabled  = $true
			Severity = 'Warning'
		}
		PSAvoidUsingWriteHost                = @{
			Enabled = $false
		}
		PSUseBOMForUnicodeEncodedFile        = @{
			Enabled = $false
		}
	}
	ExcludeRules = @('PSUseApprovedVerbs', 'PSAvoidUsingWriteHost', 'PSUseBOMForUnicodeEncodedFile', 'PSUseSingularNouns')
}