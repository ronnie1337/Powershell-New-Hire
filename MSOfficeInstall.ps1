# *****NOTES*****

#APPLICATION SERVER: APP_SERVER
#COMPANY NAME: COMPANY
#DOMAIN: DOMAIN
#IT PHONE NUMBER: PHONE_NUMBER


# =======================================================================================

using namespace System.Management.Automation.Host

# ==========================================================================================
# *****FUNCTIONS*****

# *****GET OUTLOOK OPTION*****

    function Get-OutlookOption {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
        $OutlookYes = [ChoiceDescription]::new('&Yes', 'Outlook?: Outlook Yes ')
        $OutlookNo = [ChoiceDescription]::new('&No', 'Outlook?: Outlook No')
        $options = [ChoiceDescription[]]($OutlookNo, $OutlookYes)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)
        Write-Host
        switch ($Result)
        {
            0 { 'No' }
            1 { 'Yes' }
            }
        }

# *****SEND MESSAGE TO USER SCREEN*****

    Function Send-NetMessage{ 
        <#   
        .SYNOPSIS   
        Sends a message to network computers 
  
        .DESCRIPTION   
        Allows the administrator to send a message via a pop-up textbox to multiple computers 
  
        .EXAMPLE   
        Send-NetMessage "This is a test of the emergency broadcast system.  This is only a test." 
  
        Sends the message to all users on the local computer. 
  
        .EXAMPLE   
        Send-NetMessage "Updates start in 15 minutes.  Please log off." -Computername testbox01 -Seconds 30 -VerboseMsg -Wait 
  
        Sends a message to all users on Testbox01 asking them to log off.   
        The popup will appear for 30 seconds and will write verbose messages to the console.  
 
        .EXAMPLE 
        ".",$Env:Computername | Send-NetMessage "Fire in the hole!" -Verbose 
     
        Pipes the computernames to Send-NetMessage and sends the message "Fire in the hole!" with verbose output 
     
        VERBOSE: Sending the following message to computers with a 5 delay: Fire in the hole! 
        VERBOSE: Processing . 
        VERBOSE: Processing MyPC01 
        VERBOSE: Message sent. 
     
        .EXAMPLE 
        Get-ADComputer -filter * | Send-NetMessage "Updates are being installed tonight. Please log off at EOD." -Seconds 60 
     
        Queries Active Directory for all computers and then notifies all users on those computers of updates.   
        Notification stays for 60 seconds or until user clicks OK. 
     
        .NOTES   
        Author: Rich Prescott   
        Blog: blog.richprescott.com 
        Twitter: @Rich_Prescott 
        #> 
 
    Param( 
        [Parameter(Mandatory=$True)] 
        [String]$Message, 
     
        [String]$Session="*", 
     
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)] 
        [Alias("Name")] 
        [String[]]$Computername=$env:computername, 
     
        [Int]$Seconds="5", 
        [Switch]$VerboseMsg, 
        [Switch]$Wait 
        ) 
     
    Begin 
        { 
        Write-Verbose "Sending the following message to computers with a $Seconds second delay: $Message" 
        } 
     
    Process 
        { 
        ForEach ($Computer in $ComputerName) 
        { 
            Write-Verbose "Processing $Computer" 
            $cmd = "msg.exe $Session /Time:$($Seconds)" 
            if ($Computername){$cmd += " /SERVER:$($Computer)"} 
            if ($VerboseMsg){$cmd += " /V"} 
            if ($Wait){$cmd += " /W"} 
            $cmd += " $($Message)" 
 
            Invoke-Expression $cmd 
            } 
        } 
        End 
        { 
            Write-Verbose "Message sent." 
        } 
    }


# *****LICENSE USER WITH E3 LICENSE*****

    function Get-UserLicense {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
        $AlreadyLicensedYes = [ChoiceDescription]::new('&Yes', 'Licensed?: Already Licensed')
        $AlreadyLicensedNo = [ChoiceDescription]::new('&No', 'Licensed?: Not Licensed No')
        $options = [ChoiceDescription[]]($AlreadyLicensedYes, $AlreadyLicensedNo)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)
        Write-Host
        switch ($Result)
        {
            0 { 'Yes' }
            1 { 'No' }
        }
    }

# *****GET TICKET NUMBER*****

    function Get-TicketNumber {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
        $TicketYes = [ChoiceDescription]::new('&Yes', 'Ticket Assigned: Yes')    
        $TicketNo = [ChoiceDescription]::new('&No', 'Ticket Assigned: No')
        $options = [ChoiceDescription[]]($TicketYes, $TicketNo)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)
        Write-Host
        switch ($Result)
        {
            0 { 'Yes' }
            1 { 'No' }
        }
    }

# *****PROCEED*****

    function Proceed {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
        $ProceedYes = [ChoiceDescription]::new('&Yes', 'Proceed: Yes')    
        $ProceedNo = [ChoiceDescription]::new('&No', 'Proceed: No')
        $options = [ChoiceDescription[]]($ProceedYes, $ProceedNo)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)
        Write-Host
        switch ($Result)
        {
            0 { 'Yes' }
            1 { 'No' }
        }
    }

# *****GET USER*****
       
    Function Get-User {
        $Global:UserName = Read-Host "Enter User Full Name (include . if name not found)" 
        $UserCheck = Get-ADUser $UserName -Properties DisplayName | select DisplayName
        
	    if ($UserName -eq $null){
		Write-Host "Username cannot be blank. Please re-enter username"
		Get-User
	    }
	    $EmployeeUserCheck = Get-ADUser $UserName
	    if ($EmployeeUserCheck -eq $null){
		Write-Host "Invalid username. Please verify this is the logon id / username for the account"
		Get-User
        }
        else{
        Write-Host
        Write-Host "User Located..." -ForegroundColor Green
        Sleep 1
        }
    }

# *****GET COMPUTER INFORMATION******

    Function Get-ComputerName {

        $Global:ComputerName = Read-Host "What is the computer name?"
        $ComputerCheck = Get-ADComputer $ComputerName -Properties Name | Select Name      
            if ($ComputerName -eq $null){
		    Write-Host "Computername cannot be blank. Please re-enter username" -ForegroundColor Red
		    Get-ComputerName
            }
            $ComputerUserCheck = Get-ADComputer $ComputerName
	        if ($ComputerCheck -eq $null){
		    Write-Host "Invalid computer name. Please verify the computer name" -ForegroundColor Red
		    Get-ComputerName
            }
            else{
            Write-Host
            Write-Host "Computer Located..." -ForegroundColor Green
            Sleep 1
            }
        }

# ***** TEST IF PSREMOTING IS ENABLED*****
    
function Test-PsRemoting
{
    param(
        [Parameter(Mandatory = $true)]
        $computername
    )
   
    try
    {
        $errorActionPreference = "Stop"
        $result = Invoke-Command -ComputerName $computername { 1 }
    }
    catch
    {
        Write-Verbose $_
        return $false
    }
   
    ## I've never seen this happen, but if you want to be
    ## thorough....
    if($result -ne 1)
    {
        Write-Verbose "Remoting to $computerName returned an unexpected result."
        return $false
    }
   
    $true   
}

# *****OFFICE 365 OR OFFICE 2016*****

    
   function Get-OfficeVersion {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
    
        $365ProPlus = [ChoiceDescription]::new('&Microsoft 365 ProPlus', 'Office Version: 365 ProPlus')
        $2016ProPlus = [ChoiceDescription]::new('&Office 2016 ProPlus', 'Office Version: 2016 ProPlus')

        $options = [ChoiceDescription[]]($365ProPlus, $2016ProPlus)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { '365 ProPlus' }
        1 { '2016 ProPlus' }
        }
    }


# *****SEND COMPLETION EMAIL*****

function Send-Email {

   $EmployeeEmailBody = "
        
        <style>
        h3 {color: #1E41EF;line-height: .5}
        h4 {color: black;line-height: .4;}
        p {color: black;line-height: 1}
        p1 {color: black;line-height: 1}
        p2{color: black;line-height: 1;text-transform: uppercase}
        table{border-width: 1px;border-style: solid;text-align:center;border-color: black;border-collapse: collapse;}
        th{color:white;border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;background-color:#4C5ED7}
        tr{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
        td{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
        </style>
     
        <p>Good Day,</p>
        <p>&nbsp;</p>
        <p>COMPANY IT has installed Microsoft Office ProPlus on your computer.</p>
        <p>&nbsp;</p>
        <p>To start using Microsoft Office, please launch a Microsoft Program (i.e. Word, Excel, etc.) and answer the questions as directed to logon. Please reference the <a href=https://help.DOMAIN.com/solution/articles/11000043438-how-to-logon-to-microsoft-office><font color=#1E41EF>Solution Article</font></a> on the help desk portal for more information.<br /><br /></p>
        <p>There is a slight possibility that your Excel or Word documents will not open when selected (meaning a document that is used for Microsoft Excel or Word will not open when double clicked). If this occurs please follow the instructions in the associated article <a href=https://help.DOMAIN.com/a/solutions/articles/11000047561><font color=#1e41ef>How to Set Microsoft Excel and Microsoft Word as a Default App in Windows 10</font></a>.</p>
        <p>Sincerely,</p>
        <p>&nbsp;</p>
        <p>COMPANY IT</p>
        <p>PHONE_NUMBER</p>
        <p><a href=https://help.DOMAIN.com/><font color=#1E41EF>https://help.DOMAIN.com</font></a></p>
        "
        if ($TicketNumber -eq "Yes") {
        Send-MailMessage -To "Help Desk <Help.Desk@DOMAIN.com>" -from "$AdminName <$AdminEmail>" -Subject Microsoft" "$OfficeVersion" "Installed:" "-" "Ticket[#SR-$TicketNum]"" -smtpserver smtp-relay.DOMAIN.com -Body $EmployeeEmailBody -BodyAsHtml 
        } else {
        Send-MailMessage -To "$UserFirstName $UserLastName <$UserEmailAddress>" -from "$AdminName <$AdminEmail>" -Subject Microsoft" "$OfficeVersion" "Installed:" "-" "Ticket[#SR-$TicketNum]"" -smtpserver smtp-relay.DOMAIN.com -Body $EmployeeEmailBody -BodyAsHtml 
        }
        Write-Host "Email Sent" -ForegroundColor Green
        Write-Host
        Sleep 2
    }


# *****END OF FUNCTIONS*****

# =============================================================================================================================================

# *****SET VARIABLES*****

    $PSEMailServer = "smtp-relay.DOMAIN.com"

# *****GET ADMINISTRATOR INFORMATION*****

        $AdminName = $env:UserName
        $AdminInfo = Get-ADUser -Identity $AdminName -Properties mail,GivenName,Surname
        $AdminFirstName = $AdminInfo.GivenName
        $AdminLastName = $AdminInfo.Surname
        $AdminEmail = $AdminInfo.mail
        Write-Host
        Write-Host "This script is being executed by $AdminFirstName $AdminLastName" -ForegroundColor Yellow
        Write-Host
        Sleep 1

 # *****CHECK TO SEE IF POWERSHELL MODULES AND PSEXEC IS INSTALLED*****
        
        Write-Host
        if (Get-Module -ListAvailable -Name MSOnline){
        Write-Host "MSOnline Module exists.  Continuing...." -ForegroundColor Green
        } 
        else {
        Write-Host "MSOnline Module does not exist.  Installing...." -ForegroundColor Red
        Write-Host
        Write-Host "Installing NuGet Provider...." -ForegroundColor Yellow
        Write-Host
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Write-Host "NuGet Package Provider Installed" -ForegroundColor Green
        Write-Host "Installing MSOnline Module" -ForegroundColor Yellow
        Write-Host
        Install-Module MSOnline
        Write-Host "MSOnline Module Installed Successfully"
        }
        Sleep 1
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Host
        Write-Host "ActiveDirectory Module exists.  Continuing...." -ForegroundColor Green
        } 
        else {
        Write-Host "ActiveDirectory Module does not exist.  Installing...." -ForegroundColor Red
        Write-Host
        Add-WindowsCapability -online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        Write-Host "Active Directory Module Installed" -ForegroundColor Green
        Write-Host
        }
        Sleep 1        
        if (Get-Module -ListAvailable -Name AzureAD) {
        Write-Host
        Write-Host "AzureAD Module exists.  Continuing...." -ForegroundColor Green
        } 
        else {
        Write-Host "AzureAD Module does not exist.  Installing...." -ForegroundColor Red
        Write-Host
        Install-Module AzureAD -Force
        Write-Host "MSOnline Module Installed" -ForegroundColor Green
        Write-Host
        }
        Sleep 1
        if (Test-Path C:\Tech\PStools\PsExec.exe -PathType Leaf) {
        Write-Host
        Write-Host "PsExec.exe Exists.  Continuing...." -ForegroundColor Green
        Write-Host
        }
        else {
        Write-Host "PsExec.exe does not exist.  Preparing to copy required files..." -ForegroundColor Red
        Write-Host
        Write-Host "Copying PSTools Directory to C:\Tech\PSTools" -ForegroundColor Yellow
        Write-Host
        Copy-Item -Path "\\APP_SERVER\PSTools\" -Destination "C:\Tech\" -Recurse -Force -ErrorAction Stop
        Write-Host "Done..." -ForegroundColor Green
        Write-Host
        Write-Host
        }
        Sleep 1


# *****GET USER INFORMATION*****

        Write-Host
        Get-User
        $UserInfo = Get-ADUser -Identity $UserName -Properties employeeID,givenname,mail,surname
        $UserFirstName = $UserInfo.GivenName
        $UserLastName = $UserInfo.Surname
        $UserEmailAddress = $UserInfo.Mail
        $UserEmployeeID = $UserInfo.employeeID
        Write-Host
        Write-Host "The user's email address is: $UserEmailAddress" -ForegroundColor Yellow
        $Proceed = Proceed -Title "Proceed" -Question "Do you wish to proceed?"
        Write-Host
            if ($Proceed -eq "No"){
            Write-Host "Cancelled" -ForegroundColor Red
            Exit
            }
            else {
            write-host
            Write-Host "Continuing....." -ForegroundColor Green
            sleep 2       
            }

# *****GET TICKET NUMBER*****

        $TicketNumber = Get-TicketNumber -Title "Ticket Number" -Question "Do you have a ticket number?"
            if ($TicketNumber -eq "Yes") {$TicketNum = Read-Host "What is the ticket number? (i.e. 10021)"
            Write-Host "Accepted" -ForegroundColor Green
            }
            Else {Write-Host "No ticket number assigned" -ForegroundColor Red
            Write-Host
            Sleep 2
            }

# *****GET COMPUTER NAME*****

        Get-ComputerName

# *****TEST CONNECTION TO COMPUTER*****
    
        Write-Host
        Write-Host "Testing Connectivity to $ComputerName" -ForegroundColor Yellow
        Write-Host
            if (Test-connection $ComputerName -quiet) {
            Write-Host "PC is Up.  Continuing...." -ForegroundColor Green
            } 
            Else {
            Write-Host 
            Write-Host "PC is not online. Please contact $UserName to ensure their computer is on the network" -ForegroundColor Red
            Write-Host
            exit
            }
        Sleep 1

 # *****CHECK TO SEE IF WINRM IS STARTED AND START PSREMOTING IF NOT *****

        if (!(Test-WSMan $ComputerName -ErrorAction SilentlyContinue)){
        Write-Host "Starting Windows Remote Mangement Service" -ForegroundColor Yellow
        Write-Host
        C:\Tech\PSTools\psexec.exe \\$ComputerName -s powershell Enable-PSRemoting -Force
        Write-Host "Starting Windows Remote Mangement Service" -ForegroundColor Yellow
        Get-Service -Name WinRM -ComputerName $ComputerName | Set-Service -Status Running
        Sleep 2
        Write-Host
        Write-Host "Windows Remote Mangaemet Service is now running" -ForegroundColor Green
        }
        ELSE {
        Write-Host
        Write-Host "WinRM service is running. Continuing...." -ForegroundColor Green
        }
        Sleep 1
    
    # *****WHICH VERSION OF OFFICE WOULD YOU LIKE INSTALLED?"
        
        $OfficeVersion = Get-OfficeVersion -Title "List of Office Versions" -Question "What version of Microsoft Office would you like installed?"
        Write-Host
            if ($OfficeVersion -eq "365 ProPlus") {
            Write-Host "Installing Microsoft Office 365 ProPlus" -ForegroundColor Green
            Write-Host

                        
        # *****CHECK TO SEE IF MICROSOFT 365 IS ALREADY INSTALLED*****
            
            $regkey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName) 
            $ref = $regKey.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\O365ProPlusRetail - en-us");
            if ($ref) {
            Write-Host "Microsoft Office 365 is already installed. Check with the user to ensure all is operational" -ForegroundColor Red
            Write-Host
            Exit
            }
            else {
            Write-Host "Microsoft Office 365 is not installed.  Proceeding to install" -ForegroundColor Green
            Write-Host
            } 
              
        # *****CREATE OFFICE 365 DIRECTORY*****

            Write-Host 
            Write-Host "Creating Office365 Directory (C:\Tech\Office365)" -ForegroundColor Yellow
            Write-Host
            New-Item -path "\\$ComputerName\c$\Tech\Office365" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Sleep 2
        
        # *****COPY INSTALL FILES*****

            Write-Host "Copying O365 Install Files to C:\Tech\Office365" -ForegroundColor Yellow
            Write-Host
            Copy-Item -Path "\\APP_SERVER\Office365\*" -Destination "\\$ComputerName\c$\Tech\Office365\" -Force -ErrorAction Stop
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            Sleep 2

         # *****INSTALL O365 PROPLUS*****

            $OutlookInstall = Get-OutlookOption -Title "Outlook Question" -Question "Do you want Outlook Installed?"
            if ($OutlookInstall -eq "Yes") {
            Write-Host "Microsoft Office 365 ProPlus with Outlook is now being installed on $Computer.  This may take up to 10 minutes to complete (depending on internet speeds)" -ForegroundColor Yellow
            Write-Host
            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Set-Location "C:\Tech\Office365\"; .\setup.exe /configure OfficeProPlus32.xml }
            }
            Else
            {
            Write-Host
            Write-Host "Microsoft Office 365 ProPlus without Outlook is now being installed on $ComputerName.  This may take up to 10 minutes to complete (depending on internet speeds)" -ForegroundColor Yellow
            Write-Host
            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Set-Location "C:\Tech\Office365\"; .\setup.exe /configure OfficeProPlus32_NoOutlook.xml }
            }
              
        # *****CONFIRM O365 PRO PLUS INSTALLED*****
            
            $regkey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $remoteComputer) 
            $ref = $regKey.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\O365ProPlusRetail - en-us");
            if (!$ref) {
            Write-Host "Microsoft Office 365 did not install successfully. Possible reasons include, but aren't limited to: previous versions of Office could not be uninstalled, Skype 2013 or previous is installed, not enough hard disk space, etc.  Please contact user and install manually." -ForegroundColor Red
            exit
            }
            else {
            Write-Host "Microsoft Office 365 installed successfully.  Continuing....." -ForegroundColor Green
            Write-Host "Sending Email to $Username stating the installation has completed"
            Send-Email
            } 

            # *****DO YOU WISH TO ASSIGN A LICENSE?*****

                $Proceed = Proceed -Title "Proceed" -Question "Do you wish to assign a Microsoft E3 License?"
                Write-Host
                if ($Proceed -eq "No"){
                Write-Host "You have elected to not assign a license. Sending completion email to " -ForegroundColor Red
                Send-Email
                Exit
                }
                else {
                write-host
                Write-Host "Proceeding to assign license for $Username" -ForegroundColor Yellow
                sleep 2       

            # *****IDENTIFY EXISTING LICESES ASSGINED TO USER*****

                Import-Module MSOnline
                Connect-AzureAD
                Write-Host
                Write-Host
                Sleep 2     
                $userUPN="$UserEmailAddress"
                $licensePlanList = Get-AzureADSubscribedSku
                $userList = Get-AzureADUser -ObjectID $userUPN | Select -ExpandProperty AssignedLicenses | Select SkuID 
                $userList | ForEach { $sku=$_.SkuId ; $licensePlanList | ForEach { If ( $sku -eq $_.ObjectId.substring($_.ObjectId.length - 36, 36) ) { Write-Host $_.SkuPartNumber } } }
                Write-Host
                Write-Host "Documnent License" -ForegroundColor:Yellow
                Write-Host
                Sleep 5

            # *****ASSIGN E3 LICENSE TO USER*****

                Write-Host
                $CurrentLicense = Read-Host "What license is currently assigned to the user?"
                Write-Host
                Write-Host "You entered $CurrentLicense" -ForegroundColor Yellow
                $Proceed = Proceed -Title "Proceed" -Question "Do you wish to proceed?"
                if ($Proceed -eq "No"){
                    Write-Host "Cancelled" -ForegroundColor Red
                    Exit
                    }
                    else {
                    write-host
                    Write-Host "$UserName is now assigned the following license:" -ForegroundColor Green
                    Write-Host
                    sleep 2       
                    }  


            # *****UNASSIGN EXISTING LICENSE*****
                $subscriptionFrom = "$CurrentLicense"
                $subscriptionTo="ENTERPRISEPACK"
                $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
                $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
                $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $subscriptionFrom -EQ).SkuID
                $licenses.AddLicenses = $license
                Set-AzureADUserLicense -ObjectId $userUPN -AssignedLicenses $licenses
                $licenses.AddLicenses = @()
                $licenses.RemoveLicenses =  (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $subscriptionFrom -EQ).SkuID
                Set-AzureADUserLicense -ObjectId $userUPN -AssignedLicenses $licenses

            # *****ASSIGN E3 LICENSE*****

                $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $subscriptionTo -EQ).SkuID
                $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
                $licenses.AddLicenses = $License
                Set-AzureADUserLicense -ObjectId $userUPN -AssignedLicenses $licenses

            # *****VERIFY LICENSE UPDATED SUCCESSFULLY*****
    
                $userUPN="John.Smith@DOMAIN.com"
                $licensePlanList = Get-AzureADSubscribedSku
                $userList = Get-AzureADUser -ObjectID $userUPN | Select -ExpandProperty AssignedLicenses | Select SkuID 
                $userList | ForEach { $sku=$_.SkuId ; $licensePlanList | ForEach { If ( $sku -eq $_.ObjectId.substring($_.ObjectId.length - 36, 36) ) { Write-Host $_.SkuPartNumber } } }
                Write-Host
                Write-Host
                Sleep 5
        }
        }
        ElseIf ($OfficeVersion -eq "2016 ProPlus") {
        Write-Host
        Write-Host "You have selected Office 2016 ProPlus" -ForegroundColor Yellow

        # *****CREATE OFFICE 2016 DIRECTORY*****

            Write-Host
            Write-Host "Creating Office2016 Directory (C:\Tech\Office2016)" -ForegroundColor Yellow
            Write-Host
            New-Item -path "\\$ComputerName\c$\Tech\Office2016" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            Sleep 2
        
        # *****COPY INSTALL FILES*****

            Write-Host "Copying Office 2016 Install Files to C:\Tech\Office2016" -ForegroundColor Yellow
            Write-Host
            Copy-Item -Path "\\APP_SERVER\Office2016\*" -Destination "\\$ComputerName\c$\Tech\Office2016\" -Recurse -ErrorAction Stop
            Write-Host "Done..." -ForegroundColor Green
            Sleep 2

        # *****INSTALL Office 2016*****

            Write-Host "Microsoft Office 2016 is now being installed on $ComputerName.  This may take up to 10 minutes to complete (depending on internet speeds)" -ForegroundColor Yellow
            Write-Host
            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Set-Location "C:\Tech\Office2016"; Start-Process .\Setup.exe -Verb runAS -ArgumentList '/adminfile Office2016Setup.msp' -Wait} -ErrorAction Stop
            Write-Host
            Write-Host "Microsoft Office 2016 ProPlu installed successfully" -ForegroundColor Green
            Write-Host "Sending Email to $Username stating the installation has completed"
            Send-Email
            }
            sleep 1

# *****SEND MESSAGE TO USER DISPLAY*****

        Write-Host
        Write-Host "Displaying Message: Microsoft Office has been successfully installed on this computer and an email has been sent to $UserName with instructions." -ForegroundColor Yellow
        Write-Host "message will be displayed for 60 seconds" -ForegroundColor DarkMagenta
        Send-NetMessage "Microsoft Office has been successfully installed on this computer and an email has been sent to $UserName with instructions." -ComputerName $ComputerName -Seconds 60 -VerboseMsg -Wait
        Write-Host
        Write-Progress -Activity "Sleep" -Completed
        Write-Host
        Write-Host "Message on user screen removed." -ForegroundColor:Green
        Write-Host
        Sleep 2

# *****END PROCESS*****

        Write-Host "Microsoft Office has been installed successfully, email sent to $UserName and a message has been sent to $ComputerName." -ForegroundColor Green
        Sleep 2