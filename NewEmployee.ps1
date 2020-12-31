# *****NOTES*****

#REPLICATE WITH AZURE AD: AZURE_AD
#LOG FILE SERVER: logfile
#EXCHANGE SERVER: exchangeserver
#COMPANY NAME: COMPANY
#DOMAIN: DOMAIN
#DOMAIN2: DOMAIN_2
#DOMAIN3: DOMAIN_3
#DOMAIN4: DOMAIN_4
#IT PHONE NUMBER: PHONE_NUMBER

# =======================================================================================

using namespace System.Management.Automation.Host

# FUNCTIONS

# =======================================================================================

    # *****USER EMAIL*****
    
    function Get-UserType {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
    
        $FullTimeEmployee = [ChoiceDescription]::new('&Full Time', 'User Type: Full Time')
        $TemporaryEmployee = [ChoiceDescription]::new('&Temporary', 'User Type: Temporary')
        $VendorType = [ChoiceDescription]::new(R'&Vendor', 'User Type: Vendor')

        $options = [ChoiceDescription[]]($FullTimeEmployee, $TemporaryEmployee, $VendorType)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'Full Time' }
        1 { 'Temporary' }
        2 { 'Vendor' }
        }
    }

# *****EMAIL DOMAIN*****

    function Get-EmailDomain {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
    
        $DOMAINDomain = [ChoiceDescription]::new('&DOMAIN', 'Email Domain: DOMAIN.com')
        $DOMAIN_2Domain = [ChoiceDescription]::new('&DOMAIN_2', 'EMail Domain: DOMAIN_2.com')
        $DOMAIN_3Domain = [ChoiceDescription]::new('&DOMAIN_3', 'Email Domain: DOMAIN_3.com')
        $DOMAIN_4Domain = [ChoiceDescription]::new('&SiTech', 'Email Domain: DOMAIN_4.com')

        $options = [ChoiceDescription[]]($DOMAINDomain, $DOMAIN_2Domain, $DOMAIN_3Domain, $DOMAIN_4Domain)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'DOMAIN.com' }
        1 { 'DOMAIN_2.com' }
        2 { 'DOMAIN_3.com' }
        3 { 'DOMAIN_4.com' }
        }
    }

# *****ROLE ASSIGNMENT*****

    function Get-Role {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )
    
        $AdminSelection = [ChoiceDescription]::new('&Admin', 'Role: Admin')
        $SalesSelection = [ChoiceDescription]::new('&Sales', 'Role: Sales')
        $ServiceSelection = [ChoiceDescription]::new('&Technician', 'Role: Technician')


        $options = [ChoiceDescription[]]($AdminSelection, $SalesSelection, $ServiceSelection)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'Admin' }
        1 { 'Sales' }
        2 { 'Technician' }
        }
    }

#*****GET PREFERRED NAME*****

    function Get-PreferredName {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )

        $PreferredYes = [ChoiceDescription]::new('&Yes', 'Preferred Name: Yes')    
        $PreferredNo = [ChoiceDescription]::new('&No', 'Preferred Name: No')

        $options = [ChoiceDescription[]]($PreferredNo, $PreferredYes)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'No' }
        1 { 'Yes' }
        }
    }

# *****VENDOR PASSWORD*****

    function Get-VendorPassword {

        function Get-RandomCharacters($length, $characters) {
            $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
            $private:ofs=""
            return [String]$characters[$random]
            }
 
        function Scramble-String([string]$inputString){     
            $characterArray = $inputString.ToCharArray()   
            $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
            $outputString = -join $scrambledStringArray
            return $outputString 
            }
     
    $VenPassword = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
    $VenPassword += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $VenPassword += Get-RandomCharacters -length 1 -characters '1234567890'
    $VenPassword += Get-RandomCharacters -length 1 -characters '!"§$%&/()=?}][{@#*+'
    $VenPassword = Scramble-String $VenPassword
    }

# *****REPLICATING WITH AZURE AD*****"

    function Start-Replication {

        $ADSyncSession = New-PSSession -ComputerName AZURE_AD
        Invoke-Command -Session $ADSyncSession -ScriptBlock {Import-Module -Name 'ADSync'}
        Invoke-Command -Session $ADSyncSession -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
        Remove-PSSession $ADSyncSession

        for ($i = 120; $i -gt 1; $i--){
        Write-Progress -Activity "Replicating user account $logonname@$emaildomain with O365 tenant" -SecondsRemaining $i
        Start-Sleep 1
        }
        Write-Progress -Activity "Sleep" -Completed
        Write-Host "Replication Complete" -ForegroundColor:Green
    }

# *****WAIT FOR MAILBOX CREATION*****

function Start-MailboxWait {
For ($i=0; $i -le 100; $i++) {
        Start-Sleep -Milliseconds 5000
        Write-Progress -Activity "Waiting for Mailbox Creation" -Status "Percentage Complete: $i" -PercentComplete $i -CurrentOperation "Counting ..."
        }
        }

# *****VALIDATE ALIAS EMAIL ADDRESS*****

    function Validate-proxyAddress($email){
        if (Get-ADUser -Filter "proxyAddresses -eq 'smtp:$email'"){
        return $true
        }
        elseif (Get-ADUser -Filter "mail -eq '$email'"){
        return $true
        }
        elseif (Get-ADUser -Filter "UserPrincipalName -eq 'email'"){
        return $true
        }
        return $false
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

# *****GET MANAGER*****
       
    Function Get-Manager {
        $Global:ManagerName = Read-Host "Enter Manager Full Name (include . if name not found)"
        $ManagerCheck = Get-ADUser $ManagerName -Properties DisplayName | select DisplayName
        Write-Host $ManagerName
        
	    if ($ManagerName -eq $null){
		Write-Host "Username cannot be blank. Please re-enter username"
		Get-Manager
	    }
	    $ManagerUserCheck = Get-ADUser $ManagerName
	    if ($ManagerUserCheck -eq $null){
		Write-Host "Invalid username. Please verify this is the logon id / username for the account"
		Get-Manager
        }
        else{
        Write-Host
        Write-Host "Manager Located..." -ForegroundColor Green
        Sleep 1
        }
    }

# *****GET EXPIRATION DATE*****
       
    Function Get-ExpireDate {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )

        $LastDayYes = [ChoiceDescription]::new('&Yes', 'Last Day: Yes')    
        $LastDayNo = [ChoiceDescription]::new('&No', 'Last Day: No')

        $options = [ChoiceDescription[]]($LastDayYes, $LastDayNo)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'Yes' }
        1 { 'No' }
         }
    }

# *****GET VENDOR EMAIL ACCOUNT QUESTION*****
       
    Function Get-VenEmail {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Question
        )

        $EmailYes = [ChoiceDescription]::new('&Yes', 'Email: Yes')    
        $EmailNo = [ChoiceDescription]::new('&No', 'Email: No')

        $options = [ChoiceDescription[]]($EmailNo, $EmailYes)
        $Result = $host.ui.PromptForChoice($Title, $Question, $options, 0)

        Write-Host
        switch ($Result)
        {
        0 { 'No' }
        1 { 'Yes' }
         }
    }

# *****UPLOAD ACTIVITY TO CSV FILE*****

    function SendActivity {
        $date = Get-Date -DisplayHint date
        $csvfile = "\\logfile\it\NewHire\NewHire.csv"
        $bTicketNum = "$TicketNum"
        $bName = "$Firstname $LastName"
        $bPreferredName = "$PName"
        $bEmployeeID = "$EmployeeID"
        $bManagerName = "$ManagerFullName"
        $bRole = "$Role"
        $bEmailDomain = "$EmailDomain"
        $bEmailAddress = "$LogonName@$EmailDomain"
        $bPassword = "$EmployeeID$pwsuffix"
        $bPerformedBy = "$AdminName"
        $bDatePerformed = "$date"
        $hash =@{
            "Ticket Number" = $bTicketNum
            "Name" = $bName
            "Preferred Name" = $bPreferredName
            "Employee ID" = $bEmployeeID
            "Manager Name" = $bManagerName
            "Job Role" = $bRole
            "Email Domain" = $bEmailDomain
            "Email Address" = $bEmailAddress
            "Password" = "$bPassword"
            "Performed by" = "$bPerformedBy"
            "Date Performed" = $bDatePerformed
        }
        $newRow = New-Object PsObject -Property $hash
        Export-csv $csvfile -InputObject $newRow -Append -force
        Write-Host
        Write-Host "Upload Complete" -ForegroundColor Green 
        Write-Host
    }


# *****CREATE TICKET TO CREATE CWS ACCOUNT*****

    function CreateCWSTicket{
        Sleep 1
        $URL = "https://DOMAIN.freshservice.com/helpdesk/tickets/$TicketNum.json"
        $TicketAttributes = @{}
        $TicketAttributes.Add('subject', "Create a CWS ID account for $LogonName")
        $TicketAttributes.Add('description', "Please create a CWS ID account for $LogonName in association with New Hire Request SR-$TicketNum | Manager Name: $ManagerFullName | Employee ID: $EmployeeID | Email Address: $LogonName@$EmailDomain")
        $TicketAttributes.Add('email', "$ManagerEmailAddress")
        $TicketAttributes.Add('ticket_type', 'Service Request')
        $TicketAttributes.Add('priority', 3)
        $TicketAttributes.Add('status', 2)
        $TicketAttributes.Add('category', 'CWS Requests')
        $TicketAttributes.Add('sub_category', 'CWS User Request')
        $TicketAttributes = @{"helpdesk_ticket" = $TicketAttributes}
        $TicketJSON = $TicketAttributes | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri $URL -Headers $HTTPHeaders -Body $TicketJSON
        Write-Host
    }

# *****CLOSE TICKET*****

    function CloseTicket{
        Sleep 1
        $URL = "https://DOMAIN.freshservice.com/helpdesk/tickets/$TicketNum.json"
        $TicketAttributes = @{}
        $TicketAttributes.Add("status", '5')
        $TicketAttributes = @{"helpdesk_ticket" = $TicketAttributes}
        $JSON = $TicketAttributes | ConvertTo-Json
        Invoke-RestMethod -Method Put -Uri $URL -Headers $HTTPHeaders -Body $JSON
        Write-Host
        Write-Host "Closed ticket $TicketNum" -ForegroundColor Green
        Write-Host
    }

# *****SEND EMPLOYEE NOTE TO FRESHSERVICE*****

    function SendEmployeeNote{
        Sleep 1
        $URL = "https://DOMAIN.freshservice.com/helpdesk/tickets/$TicketNum/conversations/note.json"
        $NoteAttributes = @{}
        $NoteAttributes.Add("body", "Created user account for $FirstName $LastName and uploaded information to \\logfile\it\NewHire\NewHire.csv. In addition a CWS user account creation ticket has been created.")
        $NoteAttributes.Add('private', 'true')
        $NoteAttributes = @{"helpdesk_note" = $NoteAttributes}
        $JSON = $NoteAttributes | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri $URL -Headers $HTTPHeaders -Body $JSON
        Write-Host
        Write-Host "Added Note to $TicketNum" -ForegroundColor Green
        Write-Host
    }
    
# *****SEND EMAIL TO EMPLOYEE*****

Function SendEmployeeEmail ($emailTo) 
<# This is a simple function that that sends a message. 
The variables defined below can be passed as parameters by taking them out  
and putting then in the parentheseis above. 
 
i.e. "Function Mailer ($subject)" 
 
#> 
 
{ 
   $message = @" 

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
     
        <p1><br>Good Day,</p>
        <p1>COMPANY IT has completed the user account creation process for <b>$LastName, $FirstName </b>. </p1>
        <p>Please have <b>$FirstName</b> reset their password by enrolling in the password reset portal (<a href=https://adpwreset.DOMAIN.com><font color=#1e41ef>https://adpwreset.DOMAIN.com</font></a>) using the credentials under <b>Primary Account Login Information</b> below before logging on to their email.</p>
        <p><font color=#FF0000><b>Special Note</b></font>: If $FirstName requires access to SIS please send an email to SISrequest@DOMAIN.com and the COMPANY Production Support team will take care of it for you.
        <hr>
        <p><b><h3>User Information</h3></b></p> 
        <p><b>Employee Full Name:</b><font color=""red""> $FirstName $MiddleName $LastName </font></p>
        <p><b>Employee Preferred Name:</b><font color=""red""> $PName $LastName</font></p>
        <p><b>Employee Number:</b><font color=""red""> $EmployeeID</font></p>
        <p><b>Email Address:</b><font color=""red""> $LogonName@$EmailDomain</font></p>
        <p><b>Alias Email Address:</b><font color=""red""> $PName.$LastName@$EmailDomain</font></p>
        <hr>
        <p><h3><b>Primary Account Logon Information</b></h3></p>
        <p><u><br><font color=#7412F4>Computer and Email Logon Credentials</font></u></p>
        <p><b>Logon Name:</b><font color=""red""> $LogonName@$EmailDomain</font></p>
        <p><b>Password:</b><font color=""red""> $EmployeeID$pwsuffix</font></p>
        <hr>
        <p><h3><b>Other Logon Credentials</b></h3></p>
        <table>
        <tr>
        <th>Application Name</th>
        <th>Logon Name</th>
        <th>Password</th>
        <th>URL</th>
        <th>Contact</th>
        <th>Notes</th>
        </tr>
        
        <tr>
        <td>COMPANY Email</td>
        <td>$PName.$LastName@$EmailDomain</td>
        <td>$EmployeeID$pwsuffix</td>
        <td><a href=https://outlook.office.com><font color=#1E41EF>Outlook Web Access</font></a></td>
        <td><a href=https://help.DOMAIN.com/><font color=#1E41EF>Help Desk Portal</font></a></td>
        <td>User will be instructed to change password upon initial logon.</td>
        </tr>

        <tr>
        <td>CWS</td>
        <td>Logon Name will be sent to $PName.$LastName@$EmailDomain</td>
        <td>Password will be sent to $PName.$LastName@$EmailDomain</td>
        <td><a href=https://login.cat.com/cgi-bin/login><font color=#1E41EF>SIS Web</font></a></td>
        <td><a href=https://help.DOMAIN.com/><font color=#1E41EF>Help Desk Portal</font></a></td>
        <td>User will be instructed to change password upon initial logon.</td>
        </tr>

        <tr>
        <td>Edge</td>
        <td>$FirstName.$LastName@$EmailDomain</td>
        <td>Password1</td>
        <td><a href=https://DOMAIN.convergencetraining.com/DOMAINTraining><font color=#1E41EF>Edge Website</font></a></td>
        <td><a href=mailto:edge@DOMAIN.com>edge@DOMAIN.com</a></td>
        <td>Password must be changed on initial logon. All support issues with Edge is managed by the training department.</td>
        </tr>

        <tr>
        <td>Help Desk Portal</td>
        <td>$PName.$LastName@$EmailDomain</td>
        <td>Use the same password used to logon to email</td>
        <td><a href=https://help.DOMAIN.com/><font color=#1E41EF>Help Desk Portal</font></a></td>
        <td>PHONE_NUMBER</a></td>
        <td>All support issues with the help desk portal is managed by the IT department.</td>
        </tr>
     
        <tr>
        <td>Intranet</td>
        <td>$EmployeeID</td>
        <td>Employee must register in portal to set password</td>
        <td><a href=https://intranet.DOMAIN.com/RPCi_Login.aspx><font color=#1E41EF>Company Intranet</font></a></td>
        <td><a href=https://help.DOMAIN.com/><font color=#1E41EF>Help Desk Portal</font></a></td>
        <td>It may take up to 1 week before $FirstName can register.</td>
        </tr>

        <tr>
        <td>Ultipro</td>
        <td>Employee ID + Last Name (all caps) i.e. C2000SMITH</td>
        <td>Default Password is employee birthdate in mmddyyyy format (i.e. 01291970)</td>
        <td><a href=https://n32.ultipro.com/L><font color=#1E41EF>UltiPro Website</font></a></td>
        <td><a href=mailto:hr@DOMAIN.com>hr@DOMAIN.com</a></td>
        <td>All support issues with Ultipro is managed by the HR department.</td>
        </tr>

        <tr>
        <td>Velocity</td>
        <td>$FirstName.$LastName@$EmailDomain</td>
        <td>Use the same password used to logon to email</td>
        <td><a href=https://DOMAIN.kminnovations.net/Apps/Dashboard.aspx?DashboardCode=INBOXL><font color=#1E41EF>Velocity Website</font></a></td>
        <td><a href=mailto:velocity@DOMAIN.com>velocity@DOMAIN.com</a></td>
        <td>All support issues with Velocity is managed by the saftey department.</td>
        </tr>

        </table>

        <hr>
        <p1><br>If you have any questions or concerns please place a ticket on the <a href=https://help.DOMAIN.com><font color=#1E41EF>help desk portal</font></a> and we will contact you as soon as possible.</p1>
        <br>
        <p><br>Sincerely,</p>
        <br>
        <p>COMPANY IT</p>
        <p>PHONE_NUMBER</p>
        <p><a href=https://help.DOMAIN.com/><font color=#1E41EF>https://help.DOMAIN.com</font></a></p>"
 
"@        
    $SmtpServer = "smtp-relay.DOMAIN.com"
    $EmailFrom = "<help.desk@DOMAIN.com>"
    $EMailTo = "$LogonName@$EmailDomain"
    $EmailCC = "$ManagerEmailAddress"
    $EmailAdmin = "$AdminEmail"
    $EmailSubject = "User Account Details: $FirstName $MiddleName $LastName [$EmployeeID] Ticket[#SR-$TicketNum]"
    #$emailattachment = "\\emailattachments\it\ax\AXQuickStartGuide.pdf"

    $mailmessage = New-Object System.Net.Mail.MailMessage
    $mailmessage.from =($EmailFrom)
    $mailmessage.To.add($EmailTo)
    $mailmessage.CC.Add($EmailCC)
    $mailmessage.CC.Add($EmailAdmin)
    $mailmessage.Subject = $EmailSubject
    $mailmessage.Body = $Message

    #$attachment = New-Object System.Net.Mail.Attachment($emailattachment, 'text/plain')
    #$mailmessage.Attachments.Add($attachment)

    $mailmessage.IsBodyHTML = $true
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer,25)
    $SMTPClient.Send($mailmessage)
    Write-Host "Email Sent" -ForegroundColor Green
    Write-Host
} 

# ****SEND ACTIVITY, CREATE CWS TICKET, ADD COMPLETION NOTE TO FRESHSERVICE, SEND COMPLETION EMAIL, CLOSE TICKET*****

    function SendAll {
        Write-Host "Uploading activity to \\logfile\it\NewHire\NewHire.csv" -ForegroundColor Cyan
        Write-Host
        SendActivity
        Write-Host "Successfully uploaded activity to \\logfile\it\NewHire\NewHire.csv" -ForegroundColor Green
        Write-Host
        Sleep 1
        Write-Host "Creating CWS user request for $LogonName" -ForegroundColor Cyan
        Write-Host
        CreateCWSTicket
        Write-Host "Successfully created CWS user request for $LogonName" -ForegroundColor Cyan
        Write-Host
        Sleep 1
        Write-Host "Sending completion email to $ManagerFullName and $LogonName with instructions" -ForegroundColor Cyan
        Write-Host
        SendEmployeeEmail
        Write-Host "Successfully sent email to $ManagerFullName and $LogonName" -ForegroundColor Green
        Write-Host
        Sleep 1
        Write-Host "Sending note to ticket SR-$TicketNum stating work completed" -ForegroundColor Cyan
        Write-Host
        SendEmployeeNote
        Write-Host "Successfully sent note to SR-$TicketNum" -ForegroundColor Green
        Write-Host
        Sleep 1
        Write-Host "Placing request with Freshservice to close ticket SR-$TicketNum" -ForegroundColor Cyan
        Write-Host
        CloseTicket
        Write-Host "Successfully closed ticket SR-$TicketNum" -ForegroundColor Green
        Write-Host
        Sleep 1
        Write-Host
        Write-Host "User account creation script completed for $LogonName" -ForegroundColor White
        Exit
    }

# ===========================================================================================

# *****FRESHSERVICE VARIABLES******

    $APIKey = '*******************'
    $EncodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $APIKey,$null)))
    $HTTPHeaders = @{}
    $HTTPHeaders.Add('Authorization', ("Basic {0}" -f $EncodedCredentials))
    $HTTPHeaders.Add('Content-Type', 'application/json')

# *****COMMON VARIABLES*****

    $domain = Get-WmiObject -Class Win32_ComputerSystem | select -ExpandProperty Domain
    $server = Get-ADDomain | select -ExpandProperty PDCEmulator
    $date = Get-Date -DisplayHint date
    $PSEMailServer = "smtp-relay.DOMAIN.com"
    $SmtpServer = "smtp-relay.DOMAIN.com"
    $EmpOU = "OU=Users,OU=User Accounts,DC=RPC,DC=COM"
    $pwsuffix = "DOMAIN1!"
    $VendorOU = "OU=No O365 Sync,DC=RPC,DC=COM"
    $VendorRPEmailOU = "OU=VendorRPEMail,OU=Users,OU=User Accounts,DC=RPC,DC=COM"

# *****GET ADMINISTRATOR INFORMATION*****

    $AdminName = $env:UserName
    $AdminInfo = Get-ADUser -Identity $AdminName -Properties mail,GivenName,Surname
    $AdminFirstName = $AdminInfo.GivenName
    $AdminLastName = $AdminInfo.Surname
    $AdminEmail = $AdminInfo.mail
    Write-Host
    Write-Host "Your email address is listed as $AdminEmail" -ForegroundColor Yellow
    Write-Host
    Sleep 1

# *****GET USER INFORMATION*****

    Write-Host
    Write-Host
    $FirstName = Read-Host "Enter the users first name"
    Write-Host "Accepted" -ForegroundColor Green
    Write-Host
    $MiddleName = Read-Host "Enter the users middle initial"
    Write-Host "Accepted" -ForegroundColor Green
    Write-Host
    $LastName = Read-Host "Enter the users last name"
    Write-Host "Accepted" -ForegroundColor Green
    Write-Host

 # *****GET MANAGER INFORMATION*****

    Get-Manager
    $ManagerInfo = Get-ADUser -Identity $ManagerName -Properties employeeID,givenname,mail,surname,title,name
    $ManagerFullName = $ManagerInfo.Name
    $ManagerFirstName = $ManagerInfo.GivenName
    $ManagerLastName = $ManagerInfo.Surname
    $ManagerEmailAddress = $ManagerInfo.Mail
    $ManagerEmployeeID = $ManagerInfo.employeeID
    $ManagerJobTitle = $ManagerInfo.Title
    Write-Host
    Sleep 1
    Write-Host "$FirstName $LastName's manager is:  $ManagerFullName" -ForegroundColor Cyan

# *****GET TICKET NUMBER*****

    $TicketNumber = Get-TicketNumber -Title "Ticket Number" -Question "Do you have a ticket number?"
        if ($TicketNumber -eq "No") {Write-Host "No ticket number assigned" -ForegroundColor Red
            Write-Host
            }
         else {$TicketNum = Read-Host "What is the ticket number?"
            $URL = "https://DOMAIN.freshservice.com/helpdesk/tickets/$TicketNum.json"
            $Ticket =  Invoke-RestMethod -Method Get -Uri $URL -Headers $HTTPHeaders -Body $TicketJSON
            $TicketDetails = $Ticket.helpdesk_ticket
            $TicketSubject = $TicketDetails.subject
            $TicketRequester = $TicketDetails.requester_name
            $TicketSRNumber = $TicketDetails.display_id
            $TicketCategory = $TicketDetails.item_category
            $TicketDepartment = $TicketDetails.department_name
        }

# ****VERIFY TICKET NUMBER*****

        if ($TicketSRNumber = $TicketNum) {
            Write-Host
            Write-Host "The ticket subject for ticket $TicketNum is $TicketSubject." -ForegroundColor Yellow
            $Proceed = Proceed -Title "Proceed" -Question "Do you wish to proceed?" 
            if ($Proceed -eq "No"){
                Write-Host "Cancelled" -ForegroundColor Red
                Exit
            }
            else {
                Write-Host "Continuing....." -ForegroundColor Green
                sleep 1   
            }
      }


# *****USER VARIABLES*****

    $LogonName = "$FirstName.$LastName"
    $fullname = "$FirstName $MiddleName $LastName"

# *****GET USER TYPE*****

    $UserType = Get-UserType -Title "User Type" -Question "What is the user type?"

    # *****GET EMPLOYEE INFORMATION*****

        if ($UserType -ne "Vendor") {
    
        # *****IMPORT POWERSHELL MODULES*****
        
                # *****IMPORT ACTIVE DIRECTORY MODULE*****

                    Write-Output "Importing Active Directory Module"
                    Import-Module ActiveDirectory
                    Write-Host "Done..." -ForegroundColor:Green
                    Write-Host
                    Sleep 2

                # *****IMPORT ON PREM EXCHANGE MODULE*****

                    Write-Output "Importing OnPrem Exchange Module"
                    $ExchangeServer = "exchangeserver.rpc.com"
                    $OnPrem = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServer/powershell" -Authentication Kerberos #-Credential $Creds
                    Import-PSSession $OnPrem -AllowClobber| Out-Null
                    Write-Host "Done..." -ForegroundColor:Green
                    Sleep 2

        # *****GET EMAIL DOMAIN*****

            $EmailDomain = Get-EmailDomain -Title "List of Email Domains" -Question "What is the email domain?"
            Write-Host
            Write-Host "Accepted" -ForegroundColor Green
            sleep 1

        # *****GET PREFERRED NAME*****
        
            $PreferredName = Get-PreferredName -Title "Preferred Name Question" -Question "Does the user have a preferred name?"

                if ($PreferredName -eq "Yes"){
                $PName = Read-Host "What is the preferred name?" 
                Write-Host "Checking to see if Alias name is available" -ForegroundColor Yellow
       
                # *****CHECKING TO SEE IF ALIAS EXISTS*****
           
                    $AliasCheck = Validate-proxyAddress "$PName.$LastName@$EmailDomain"
                        if($AliasCheck -eq "True")
                        {
                        Write-Host
                        Write-Host "WARNGING: New user conflicts with existing user!!! Contact employee to determine alternate email alias." -ForegroundColor Red 
                        Sleep 8
                        }
                        else {
                        write-Host
                        Write-Host "No alias conflicts detected" -ForegroundColor Green
                        }
                        Sleep 3
                        }
                        elseif ($PreferredName -eq "No") {$PName = "$FirstName"
                        Write-Host "$FirstName is the Preferred Name" -ForegroundColor Green
                        }
    
        # *****GET ROLE*****

            $Role = Get-Role -Title "COMPANY Roles" -Question "What role will the employee have?"
            Write-Host
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host
            sleep 1

        # *****GET EMPLOYEE ID*****

            $EmployeeID = Read-Host "Enter in the Employee ID"
            Write-Host
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host
            Sleep 1

        # *****CHECK TO SEE IF AD ACCOUNT EXISTS IN DOMAIN*****

            Write-Host "Checking to see if account exists in domain." -ForegroundColor Yellow
            Write-Host
            Do {
                If ($(Get-ADUser -Filter {SamAccountName -eq $LogonName})) {
                Write-Host "WARNING: Logon name" $LogonName.toUpper() "already exists!!" -ForegroundColor:Red
                $i++
                $LogonName = $firstname + "." + $lastname +$i
                Write-Host
                Write-Host "Changing Logon name to" $LogonName.toUpper() -ForegroundColor:Yellow
                Write-Host
                $taken = $true
                sleep 4
                } 
                else {
                $taken = $false
                }
                } 
                Until ($taken -eq $false)
                $LogonName = $LogonName.toLower()
                Write-Host
                Sleep 5
                $EmpPassword = ConvertTo-SecureString $EmployeeID$pwsuffix -asplaintext -force
                Write-Host

        # *****SUMMARY OF OPTIONS*****
            Write-Host "======================================="
            Write-Host
            Write-Host "Ticket Number:            SR-$TicketNum"
            Write-Host "Manager's Name:           $ManagerName"
            Write-Host "Firstname:                $FirstName"
            Write-Host "Middle Initial:           $MiddleName"
            Write-Host "Lastname:                 $LastName"
            Write-Host "Display name:             $firstname $lastname"
            Write-Host "Preferred Name:           $PName $LastName"
            Write-Host "Logon name:               $LogonName"
            Write-Host "Password:                 $EmployeeID$pwsuffix"
            Write-Host "Email Address:            $LogonName@$EmailDomain"
            Write-Host "Preferred Email Address:  $PName.$LastName@$EmailDomain"
            Write-Host "Employee ID               $EmployeeID"
            Write-Host "OU:                       $EmpOU"
            Write-Host "Role:                     $Role"
            Write-Host
            Write-Host "======================================="
            Write-Host
        
        # *****PROCEED TO CREATE ACCOUNT*****
            Write-Host "Continuing will create the account." -ForegroundColor:Green
            Write-Host
            $Proceed = Proceed -Title "Proceed" -Question "Do you wish to proceed?"
            Write-Host

                if ($Proceed -eq "No"){
                Write-Host "Cancelled" -ForegroundColor Red
                Exit
                }
                elseif ($Proceed -eq "Yes"){
                write-host

            # *****CREATE AD ACCOUNT*****

                Write-Host "Proceeding to create account" -ForegroundColor Green
                Write-Host       
                New-RemoteMailbox -Name $fullname -FirstName $firstname -LastName $lastname -DisplayName "$PName $LastName" -SamAccountName $LogonName -UserPrincipalName $LogonName@$EmailDomain -PrimarySmtpAddress $LogonName@$EmailDomain -Password $EmpPassword -OnPremisesOrganizationalUnit $EmpOU -DomainController $Server
                Sleep 3

            # *****ADD EMPLOYEE ID TO AD ATTRIBUTES*****

                Write-Host
                Write-Host
                Write-Host "Adding Employee ID to the new user account." -ForegroundColor Yellow
                Get-ADUser $LogonName -Server $Server | Set-ADUser -Server $Server -EmployeeNumber $EmployeeID -EmployeeID $EmployeeID
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3
            }

            # *****SET DESCRIPTION TO USER ACCOUNT*****

                Write-Host "Adding Description to Account" -ForegroundColor Yellow
                Set-Aduser -Identity "$LogonName" -Description "Account Created on $date by $AdminName"
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****SET MANAGER*****

                if ($TicketNumber -eq "No") {
                Write-Host "Adding Manager to AD User Account" -ForegroundColor Yellow
                set-aduser -identity $LogonName -Manager $ManagerName
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3
                }
                Else {
                Write-Host "Adding Manager to AD User Account" -ForegroundColor Yellow
                set-aduser -identity $LogonName -Manager $ManagerName
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3
                }

            # *****CREATE ALIAS EMAIL ACCOUNT*****

                if ($PreferredName -eq "Yes") {
                Write-Host "Creating Alias Account" -ForegroundColor Yellow
                Set-ADUser -Identity "$LogonName" -Add @{ProxyAddresses="SMTP:$PName.$LastName@$EmailDomain"}
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3
                }

            # *****ADD TECHNICAN TO SVC_TECH_LA SECURITY GROUP*****
                
                if ($Role -eq "Technician") {
                Write-Host "Adding $FirstName $LastName to SVC_TECH_LA Security Group" -Foreground Yellow
                Add-ADGroupMember -identity "SVC_TECH_LA" -Members $LogonName 
                Write-Host "Done...." -ForegroundColor: Green
                Write-Host
                Write-Host
                Sleep 3
                }

            # *****ADD DEFAULT LOGON SCRIPT TO USER ACCOUNT*****

                Write-Host "Adding DefaultLogon Script to New User Account." -ForegroundColor Yellow
                Set-ADUser -Identity $logonname -ScriptPath "DefaultLogon.bat"
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

 
            # *****REPLICATE WITH O365*****

                Start-Replication

            # *****CONNECT TO MSONLINE*****
        
                Write-Host
                Write-Host "Signing on to O365" -ForegroundColor Yellow
                Write-Host 
                Write-Output "Creating Exchange Online Session"
                #Import-Module MSOnline
                Connect-MsolService
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 2

            # *****ASSIGNING O365 F1 LICENSE*****
        
            Write-Host "Assigning Microsoft O365 F1 License"
            Write-Host 
            Write-Host           
            Set-MsolUser -UserPrincipalName $logonname"@"$emaildomain -UsageLocation US
            Set-MsolUserLicense -UserPrincipalName $logonname"@"$emaildomain -AddLicenses reseller-account:DESKLESSPACK
            Write-Host "Successfully Assigned O365 F1 License" -ForegroundColor:Green
            Write-Host
            Write-Host

            # *****ENABLE MFA *****
   
            Write-Host "Enforcing MFA for $LogonName" -ForegroundColor Yellow
            Write-Host
            Write-Host
            $mf= New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
            $mf.RelyingParty = “*”
            $mf.State = "Enforced"
            $mfa = @($mf)
            Set-MsolUser -UserPrincipalName $logonname"@"$EmailDomain -StrongAuthenticationRequirements $mfa
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            Sleep 1

            # *****WAIT FOR EMAIL ACCOUNT TO BE CREATED IN O365*****

            Start-MailboxWait

            # *****REPLICATE WITH O365*****

            # Start-Replication

            Sleep 1
            Write-Host
            Write-Host "Account Successfully Created" -ForegroundColor Green
            Sleep 1

            # *****COMPLETE NEW HIRE PROCESS*****

            SendAll

    }

    else {

    # *****CREATE VENDOR ACCOUNT*****

    # ****IMPORT POWERSHELL MODULES*****

        # *****IMPORT ACTIVE DIRECTORY MODULE*****

            Write-Output "Importing Active Directory Module"
            Import-Module ActiveDirectory
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            sleep 2
  
        # *****IMPORT ON PREM EXCHANGE MODULE*****
           
            $ExchangeServer = "exchangeserver.rpc.com"
            $OnPrem = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServer/powershell" -Authentication Kerberos
            Write-Output "Importing OnPrem Exchange Module"
            Import-PSSession $OnPrem -AllowClobber| Out-Null
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            sleep 2

        # *****GET VENDOR EMAIL ADDRESS*****

            $VendorEmail = Read-Host "What is the vendor's email address?"
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host

        # *****GET VENDOR COMPANY NAME*****

            $VendorCompany = Read-Host "What is the Vendor's Company Name?"
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host

        # *****GET VENDOR TITLE*****

            $VendorTitle = Read-Host "What is the Vendor's Title?"    
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host
            sleep 2

        # *****VENDOR REQUIRE COMPANY EMAIL ACCOUNT?*****

            $RPEmail = Get-VenEmail -Title "Vendor Require RP Email?" -Question "Does the Vendor Require a COMPANY Email Account?"   
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host
            sleep 2

        # *****GET ACCOUNT EXPIRATION DATE*****
            
            $ExpireDate = Get-ExpireDate -Title "Expiration Date Question" -Question "Did the Manager List When the Vendor Will Leave?"
            if($ExpireDate -eq "Yes") {
                $ExDate = Read-Host "Enter Date of Vendor's Last Day (i.e. 01/30/2020)"
                    if (($ExDate -as [DateTime]) -ne $null) {
                    $ExDate = [DateTime]::Parse($ExDate)
                    Write-Host = "The Expriation Date is $ExDate" -ForegroundColor Yellow
                    }
                    else {
                    'You did not enter a valid date!'
                    }
                } Else {
                $NoExDate = (get-date).AddYears(1)
                Write-Host = "The Expriation Date is $NoExDate" -ForegroundColor Yellow
                                }
              
            Write-Host "Accepted" -ForegroundColor Green
            Write-Host
            sleep 2

        
        # *****CHECKING TO SEE IF ACCOUNT EXISTS*****

            Write-Host "Checking to see if account exists in domain."
            Write-Host
            Do {
            If ($(Get-ADUser -Filter {SamAccountName -eq $LogonName})) {
            Write-Host "WARNING: Logon name" $LogonName.toUpper() "already exists!!" -ForegroundColor:Green
            $i++
            $LogonName = $firstname + "." + $lastname +$i
            Write-Host
            Write-Host "Changing Logon name to" $LogonName.toUpper() -ForegroundColor:Red
            Write-Host
            $taken = $true
            sleep 4
            } 
            else {
            $taken = $false
            }
            } 
            Until ($taken -eq $false)
            $LogonName = $LogonName.toLower()
            
        
        # *****GET VENDOR PASSWORD*****

            function Get-RandomCharacters($length, $characters) {
                $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
                $private:ofs=""
            return [String]$characters[$random]
            }
 
            function Scramble-String([string]$inputString){     
                $characterArray = $inputString.ToCharArray()   
                $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
                $outputString = -join $scrambledStringArray
                return $outputString 
            }
 
            $VenPassword = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
            $VenPassword += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
            $VenPassword += Get-RandomCharacters -length 1 -characters '1234567890'
            $VenPassword += Get-RandomCharacters -length 1 -characters '!"§$%&/()=?}][{@#*+'
            $VenPassword = Scramble-String $VenPassword
          
            $VendorPassword = ConvertTo-SecureString '$VenPassword' -asplaintext -force
            Write-Host

        # *****VENDOR SUMMARY*****

            Write-Host "======================================="
            Write-Host
            Write-Host "Firstname:                $FirstName"
            Write-Host "Middle Initial:           $MiddleName"
            Write-Host "Lastname:                 $LastName"
            Write-Host "Display name:             $firstname $lastname"
            Write-Host "Logon name:               $LogonName"
            Write-Host "Password:                 $VenPassword"
            if($ExpireDate -eq "Yes"){
            Write-Host "Expiration Date:          $ExDate"
            }else {
            Write-Host "Expiration Date:          $NoExDate"
            }
            if($RPEmail -eq "Yes"){
            Write-Host "RP Email Address:         $LogonName@DOMAIN.com"
            }
            Write-Host "Email Address:            $VendorEmail"
            if($RPEmail -eq "No"){
            Write-Host "OU:                       $VendorOU"
            }else {
            Write-Host "OU:                       $VendorRPEmailOU"
            }
            Write-Host
            Write-Host "======================================="
            Write-Host

        # *****PROCEED?*****
             
            Write-Host "Continuing will create the account." -ForegroundColor:Green
            Write-Host
            $Proceed = Proceed -Title "Proceed" -Question "Do you wish to proceed?"
            Write-Host

                if ($Proceed -eq "No"){
                Write-Host "Cancelled" -ForegroundColor Red
                Exit
                }
                elseif ($Proceed -eq "Yes"){
                write-host

            # *****CREATE ACCOUNT*****

                if($RPEmail -eq "No"){
                New-RemoteMailbox -Name $fullname -FirstName $firstname -LastName $lastname -DisplayName "$FirstName $LastName (Vendor)" -SamAccountName $logonname -UserPrincipalName $logonname@DOMAIN.com -PrimarySmtpAddress $VendorEmail -Password $VendorPassword -OnPremisesOrganizationalUnit $VendorOU -DomainController $Server
                Sleep 3
                } else {
                New-RemoteMailbox -Name $fullname -FirstName $firstname -LastName $lastname -DisplayName "$FirstName $LastName (Vendor)" -SamAccountName $logonname -UserPrincipalName $logonname@DOMAIN.com -PrimarySmtpAddress $LogonName@DOMAIN.com -Password $VendorPassword -OnPremisesOrganizationalUnit $VendorRPEmailOU -DomainController $Server
                Sleep 3
                }

            # *****SET DESCRIPTION*****

                Write-Host
                Write-Host "Adding Description to Account" -ForegroundColor Yellow
                Set-Aduser -Identity "$LogonName" -Description "Account Created on $date by $AdminName - Vendor Email Address is $VendorEmail"
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****SET MANAGER*****

                Write-Host "Adding Manager to AD User Account" -ForegroundColor Yellow
                Set-aduser -identity $LogonName -Manager $ManagerName
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****SET ORGANIZATION AND TITLE*****

                Write-Host "Adding Vendor Organization and Title" -ForegroundColor Yellow
                Set-ADUser -Identity "$LogonName" -Company "$VendorCompany"
                Set-ADUser -Identity "$LogonName" -Title "$VendorTitle"
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****ADD DEFAULT LOGON SCRIPT TO USER ACCOUNT*****

                Write-Host "Adding DefaultLogon Script to New User Account." -ForegroundColor Yellow
                Set-ADUser -Identity $logonname -ScriptPath "DefaultLogon.bat"
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****SET ACCOUNT EXPIRATION DATE*****

                Write-Host "Setting Expiration Date" -ForegroundColor Yellow
                if($ExpireDate -eq "Yes") {
                Set-ADAccountExpiration -Identity "$LogonName" -DateTime $ExDate
                } else {
                Set-ADAccountExpiration -Identity "$LogonName" -DateTime $NoExDate
                }
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 3

            # *****CREATE O365 EMAIL FOR VENDOR*****

            if($RPEmail -eq "Yes"){
       
            # *****REPLICATE WITH O365*****

                Start-Replication

            # *****CONNECT TO MSONLINE*****
        
                Write-Host
                Write-Host "Signing on to O365" -ForegroundColor Yellow
                Write-Host 
                Write-Output "Creating Exchange Online Session"
                #Import-Module MSOnline
                Connect-MsolService
                Write-Host "Done..." -ForegroundColor:Green
                Write-Host
                Write-Host
                Sleep 2

            # *****ASSIGNING O365 F1 LICENSE*****
        
            Write-Host "Assigning Microsoft O365 F1 License"
            Write-Host 
            Write-Host           
            Set-MsolUser -UserPrincipalName $logonname"@DOMAIN.com" -UsageLocation US
            Set-MsolUserLicense -UserPrincipalName $logonname"@DOMAIN.com" -AddLicenses reseller-account:DESKLESSPACK
            Write-Host "Successfully Assigned O365 F1 License" -ForegroundColor:Green
            Write-Host
            Write-Host

            # *****ENABLE MFA *****
   
            Write-Host "Enforcing MFA for $LogonName" -ForegroundColor Yellow
            Write-Host
            Write-Host
            $mf= New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
            $mf.RelyingParty = “*”
            $mf.State = "Enforced"
            $mfa = @($mf)
            Set-MsolUser -UserPrincipalName $logonname"@DOMAIN.com" -StrongAuthenticationRequirements $mfa
            Write-Host "Done..." -ForegroundColor Green
            Write-Host
            Write-Host
            Sleep 1

            # *****REPLICATE WITH O365*****

            Start-Replication   
            
            }          

            # *****EMAIL ADMIN AND TICKET*****

                Write-Host "Sending Email to $AdminName $Manager Name and Ticket SR-$TicketNum"
                Write-Host
                Sleep 1
                if($ExpireDate -eq "Yes"){

                $VendorEmailBody = "

                    <style>
                    h3 {color: #1E41EF;line-height: .5}
                    h4 {color: black;line-height: .4;}
                    p {color: black;line-height: 1}
                    p1 {color: black;line-height: 1}
                    table{border-width: 1px;border-style: solid;text-align:center;border-color: black;border-collapse: collapse;}
                    th{color:white;border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;background-color:#4C5ED7}
                    tr{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
                    td{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
                    </style>
     
                    <p1><br>Good Day,</p>
                    <p1>COMPANY IT has completed the user account creation process for the vendor <b>$LastName, $FirstName </b> (Ticket # <font color=""red"">SR-$TicketNum)</font>. Please ensure you share the following credntials with <b>$FirstName</b> so they are able to logon and access COMPANY's systems. </p1>
                    <hr>
                    <p><b><h3>User Information</h3></b></p> 
                    <p><b>Vendor Full Name:</b><font color=""red""> $FirstName $MiddleName $LastName </font></p>
                    <p><b>Email Address:</b><font color=""red""> $VendorEmail</font></p>
                    <hr>
                    <p><h3><b>Primary Account Logon Information</b></h3></p>
                    <p><u><br><font color=#7412F4>Computer and Email Logon Credentials</font></u></p>
                    <p><b>Logon Name:</b><font color=""red""> $FirstName.$LastName@DOMAIN.com</font></p>
                    <p><b>Password:</b><font color=""red""> $VenPassword</font></p>
                    <p><b>Account Expiration Date:</b><font color=""red""> $ExDate</font></p>
                    <hr>
                    <p1><br>If you have any questions or concerns please update the ticket on the <a href=https://help.DOMAIN.com/helpdesk/tickets/$TicketNum><font color=#1E41EF>help desk portal</font></a> and we will contact you as soon as possible.</p1>
                    <br>
                    <p><br>Sincerely,</p>
                    <br>
                    <p>COMPANY IT</p>
                    <p>PHONE_NUMBER</p>
                    <p><a href=https://help.DOMAIN.com/><font color=#1E41EF>https://help.DOMAIN.com</font></a></p>
                    "
                if ($TicketNumber -eq "Yes") {
                Send-MailMessage -To "$AdminName <$AdminEmail>", "$ManagerName <$ManagerEmailAddress>", "Help Desk <help.desk@DOMAIN.com>" -from "AdminName <$AdminEmail>" -Subject User" "Account" "Details:" "$FirstName" "$MiddleName" "$LastName" "["$EmployeeID"]"-"Ticket[#SR-$TicketNum]"" -Body $EmployeeEmailBody -BodyAsHtml
                } else {
                Send-MailMessage -To "$AdminName <$AdminEmail>", "$ManagerName <$ManagerEmailAddress>" -from "Help Desk <help.desk@DOMAIN.com>" -Subject User" "Account" "Details:" "$FirstName" "$MiddleName" "$LastName" "["$EmployeeID"]"" -Body $EmployeeEmailBody -BodyAsHtml
                }
                Write-Host "Email Sent" -ForegroundColor Green
                Write-Host
                Sleep 1
                Write-Host
                Write-Host "Account Successfully Created" -ForegroundColor Green
                Sleep 1
                } else {
                $VendorEmailBody = "

                    <style>
                    h3 {color: #1E41EF;line-height: .5}
                    h4 {color: black;line-height: .4;}
                    p {color: black;line-height: 1}
                    p1 {color: black;line-height: 1}
                    table{border-width: 1px;border-style: solid;text-align:center;border-color: black;border-collapse: collapse;}
                    th{color:white;border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;background-color:#4C5ED7}
                    tr{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
                    td{border-width: 1px;padding: 3px;border-style: solid;text-align:center;border-color: black;}
                    </style>
     
                    <p1><br>Good Day,</p>
                    <p1>COMPANY IT has completed the user account creation process for the Vendor <b>$LastName, $FirstName </b> (Ticket # <font color=""red"">SR-$TicketNum)</font>. Please ensure you share the following credntials with <b>$FirstName</b> so they are able to logon and access COMPANY's systems. </p1>
                    <hr>
                    <p><b><h3>User Information</h3></b></p> 
                    <p><b>Vendor Full Name:</b><font color=""red""> $FirstName $MiddleName $LastName </font></p>
                    <p><b>Email Address:</b><font color=""red""> $VendorEmail</font></p>
                    <hr>
                    <p><h3><b>Primary Account Logon Information</b></h3></p>
                    <p><u><br><font color=#7412F4>Computer and Email Logon Credentials</font></u></p>
                    <p><b>Logon Name:</b><font color=""red""> $FirstName.$LastName@DOMAIN.com</font></p>
                    <p><b>Password:</b><font color=""red""> $VenPassword</font></p>
                    <p><b>Account Expiration Date:</b><font color=""red""> $NoExDate</font></p>
                    <hr>
                    <p1><br>If you have any questions or concerns please update the ticket on the <a href=https://help.DOMAIN.com/helpdesk/tickets/$TicketNum><font color=#1E41EF>help desk portal</font></a> and we will contact you as soon as possible.</p1>
                    <br>
                    <p><br>Sincerely,</p>
                    <br>
                    <p>COMPANY IT</p>
                    <p>PHONE_NUMBER</p>
                    <p><a href=https://help.DOMAIN.com/><font color=#1E41EF>https://help.DOMAIN.com</font></a></p>
                    "
                if ($TicketNumber -eq "Yes") {
                Send-MailMessage -To "$AdminName <$AdminEmail>", "$ManagerName <$ManagerEmailAddress>", "Help Desk <help.desk@DOMAIN.com>" -from "AdminName <$AdminEmail>" -Subject User" "Account" "Details:" "$FirstName" "$MiddleName" "$LastName" "["$EmployeeID"]"-"Ticket[#SR-$TicketNum]"" -Body $EmployeeEmailBody -BodyAsHtml
                } else {
                Send-MailMessage -To "$AdminName <$AdminEmail>", "$ManagerName <$ManagerEmailAddress>" -from "Help Desk <help.desk@DOMAIN.com>" -Subject User" "Account" "Details:" "$FirstName" "$MiddleName" "$LastName" "["$EmployeeID"]"" -Body $EmployeeEmailBody -BodyAsHtml
                }
                Write-Host "Email Sent" -ForegroundColor Green
                Write-Host
                Sleep 1
                Write-Host
                Write-Host "Account Successfully Created" -ForegroundColor Green
                Sleep 1
                }
            }
         }
          
Get-PSSession | Remove-PSSession  
