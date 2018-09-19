@{
    # Some defaults for all dependencies
    PSDependOptions = @{
        Target = '$ENV:USERPROFILE\Documents\WindowsPowerShell\Modules'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'ProgramManagement' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'WinSSH' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    # When you `Install-Module UniversalDashboard.Community`, there is an interactive prompt to accept agreement,
    # which is why this currently can't be used.
    <#
    'UniversalDashboard.Community' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    #>
}
