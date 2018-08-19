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
    'UniversalDashboard.Community' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'PreRelease'
    }
}
