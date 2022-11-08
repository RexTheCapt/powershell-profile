$psprofileversion = "Dev v1"

#If the file does not exist, create it.
if (-not(Test-Path -Path $PROFILE -PathType Leaf)) {
    try {
        $path = Split-Path $PROFILE -Parent
        $path = $path+'\'

        if (!(Test-Path $path)) {
            New-Item -ItemType Directory $path
        }

        Invoke-RestMethod https://github.com/RexTheCapt/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -o $PROFILE
        Write-Host "The profile @ [$PROFILE] has been created."
    }
    catch {
       throw $_.Exception.Message
    }
}
# If the file already exists, show the message and do nothing.
else {
		Get-Item -Path $PROFILE | Move-Item -Destination oldprofile.ps1
		Invoke-RestMethod https://github.com/RexTheCapt/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -o $PROFILE
		Write-Host "The profile @ [$PROFILE] has been created and old profile removed."
}
& $profile


$confTitle = "Minimal install"
$confQuestion = "Do an minimal install?"
$confChoices = "&Yes", "&No"
$conf = $host.ui.PromptForChoice($confTitle, $confQuestion, $confChoices, 1)

switch ($conf) {
    0 {  }
    1 {
        # OMP Install
        #
        winget install -e --accept-source-agreements --accept-package-agreements JanDeDobbeleer.OhMyPosh
        
        # Font Install
        Invoke-RestMethod https://github.com/ryanoasis/nerd-fonts/releases/download/v2.1.0/CascadiaCode.zip?WT.mc_id=-blog-scottha -o cove.zip
    }
    Default {  }
}

