@{

  RootModule           = 'cJEA.psm1'

  ModuleVersion        = '1.0.0'

  GUID                 = '27bc2c0c-d98e-466d-9af4-033a48a41358'

  Author               = 'Glorious DSC Community'

  CompanyName          = 'Glorious DSC Community'

  Copyright            = 'Copyright the DSC Community contributors. All rights reserved.'

  Description          = 'This module contains resources to configure Just Enough Administration endpoints.'

  PowerShellVersion    = '5.1'

  NestedModules        = @()

  FunctionsToExport    = @(
    'ConvertTo-Expression'
  )

  VariablesToExport    = @()

  AliasesToExport      = @()

  DscResourcesToExport = @('JeaRoleCapabilities', 'JeaSessionConfiguration')

  PrivateData          = @{

    PSData = @{

      Tags         = @('DesiredStateConfiguration', 'DSC', 'DSCResource', 'JEA', 'JustEnoughAdministration', 'Role', 'Capability', 'Role Capability', 'Session', 'Configuration', 'Session Configuration')

      LicenseUri   = 'https://github.com/yangxinyun/cJEA/blob/main/LICENSE'

      ProjectUri   = 'https://github.com/yangxinyun/cJEA'

      IconUri      = 'https://vectorified.com/images/powershell-icon-20.png'

      ReleaseNotes = 'Fixed JEASessionConfiguration resource failure because of WinRM restart.'
    }
  }
}
