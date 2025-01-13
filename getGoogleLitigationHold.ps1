<#
    .SYNOPSIS
        This script lists users on litigation hold using the Google Workspace API.
        The code demonstrates the authentication flow with Google Cloud Platform (GCP) logging in with a client type of web application.
        This avoids the need to store Service Account private key.
        The will require consent from the user to access the Google Workspace API.
        The user signing in to give the consent can be chosen at the login screen.

    .DESCRIPTION    
        It uses a refresh token to get an access token.
        If the refresh token is not found, the script will prompt the user to authenticate (3LO) to get a new refresh token.
        The access token is used to make a POST request to the Google Workspace API to list users on litigation hold.


    .NOTES
        File Name      : listLitholdUsers.ps1
        Author         : Michael Maher
        Prerequisite   : PowerShell 5.1 or LATER

        For more information on GCP authentication, refer to the official documentation:
        https://cloud.google.com/docs/authentication/getting-started

    .EXAMPLE
     
        https://vault.googleapis.com/v1/matters/**********************/holds
        {
        "holds": [
            {
            "updateTime": "2024-12-13T08:03:04.716Z", 
            "name": "Default Gmail Legal Hold", 
            "orgUnit": {
                "holdTime": "2024-12-13T08:03:04.716Z", 
                "orgUnitId": "id:****************"
            }, 
            "query": {
                "mailQuery": {}
            }, 
            "corpus": "MAIL", 
            "holdId": "*********************"
            }
        ]
        }

        https://vault.googleapis.com/v1/matters/**********************/holds/*****************

        {
        "updateTime": "2024-12-13T08:03:04.716Z", 
        "name": "Default Gmail Legal Hold", 
        "orgUnit": {
            "holdTime": "2024-12-13T08:03:04.716Z", 
            "orgUnitId": "id:******************"
        }, 
        "query": {
            "mailQuery": {}
        }, 
        "corpus": "MAIL", 
        "holdId": "*******************"
        }

        https://vault.googleapis.com/v1/matters/****************/holds/***************/accounts

        {
        "accounts": [
            {
            "holdTime": "2024-12-13T11:25:23.410Z", 
            "email": "mmaher@test.io", 
            "accountId": "*******************************"
            }
        ]
        }

        Important - This API will only list individually specified accounts covered by the hold. It will not list accounts that are covered by an org unit hold.

        To list accounts covered by an org unit hold, use the following API:
        /admin/directory/v1/users?domain=domain.com&query=orgUnitPath=/Sales
            or, url encoded: 
        /admin/directory/v1/users?domain=example.com&query=orgUnitPath%3D%2FSales
#>
[CmdletBinding()]
param()

#region Variables

$kScript = 'listLitholdUsers'
Set-Location E:\Scripts\GoogleWorkspace
$refresh_token = $null
$delegatedUser = 'ADAccountWhichWillRunTheScheduledTask-svc'
#endregion

#region Retrieve stored credentials

Write-Verbose "Getting Stored Client Secret Credential"

$client_id = '*************************************************.apps.googleusercontent.com'
$client_secretSecureString = Get-SavedCredential -UserName $delegatedUser -Context $client_id
$csBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secretSecureString.Password)
$client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($csBSTR)


Write-Host "Checking for stored refresh token"

if ($null -eq (Get-SavedCredential -UserName $delegatedUser -Context $client_id -NoPrompt -ErrorAction SilentlyContinue)) {
    Write-Verbose "No Refresh Token found"
    $refresh_token = "needed"
}Else {
    Write-Verbose "Found a Refresh Token"
    $refresh_tokenSecureString = Get-SavedCredential -UserName $delegatedUser -Context $client_id
    $rtBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($refresh_tokenSecureString.Password)
    $refresh_token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($rtBSTR)
}
#endregion


#region Get a Refresh Token - only needed once

if ($refresh_token -eq "needed"){
    Write-Host "Starting 3-legged auth process to request user consent and get refresh token"

    # Include statements for .net Assemblies
    Add-Type -AssemblyName System.Web
    Add-Type -AssemblyName System.Runtime

    $BaseUrl = "https://accounts.google.com/o/oauth2/auth"
    $redirect_uri = "http://localhost:65432/"
    $LandingPage = "LandingPage.html"

    if ([string]::IsNullOrEmpty($client_id) -or [string]::IsNullOrEmpty($client_secret)) {
        "Secret values need to be filled out before running, please double check your Client Id and your Client Secret"
        exit 1
    }


    $webPageResponse = Get-Content ./3LO/$LandingPage
    <# Encode and calc the length for use later #>
    $webPageResponseEncoded =  [System.Text.Encoding]::UTF8.GetBytes($webPageResponse)
    $webPageResponseLength = $webPageResponseEncoded.Length

    <# Start up our lightweight HTTP Listener for the OAuth Response #>
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirect_uri)
    $listener.Start()

    <# Build our OAuth Query string #>
    $uri = New-Object System.UriBuilder -ArgumentList $BaseUrl
    $query = [System.Web.HttpUtility]::ParseQueryString($uri.Query)

    $query["client_id"] = $client_id
    $query["redirect_uri"] = $redirect_uri

    <# 
        ! Tip !
        Use $query["prompt"] = "consent" if the user has already authorized the app and you need to add a scope
        Google might not issue a new refresh token. 
        Adding prompt=consent to your authorization request can force Google to show the consent screen again and issue a new refresh token
    #>
    $query["response_type"] = "code"
    $query["scope"] =  "https://www.googleapis.com/auth/ediscovery.readonly https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.orgunit.readonly"
    #$query["prompt"] = "select_account"
    $query["prompt"] = "consent"
    $query["access_type"] = "offline"

    $uri.Query = $query.ToString()

    Write-Verbose $uri.Query

    <# Open up the browser for the User to OAuth in #>
    Start-Process $uri.Uri
    

    <# Waits for a response from the OAuth website#>
    $context = $listener.getContext()

    <# You can fetch any other necessary response values here #>
    $code = $context.Request.QueryString["code"]

    <# Write out our landing page for the user #>
    $response = $context.response
    $response.ContentLength64 = $webPageResponseLength
    $response.ContentType = "text/html; charset=UTF-8"
    $response.OutputStream.Write($webPageResponseEncoded, 0, $webPageResponseLength)
    $response.OutputStream.Close()

    <# Close the HTTP Listener #>
    $listener.Stop()

    # Exchange the OAuth code for an access token
    $body = "code=$code&redirect_uri=$redirect_uri&client_id=$client_id&client_secret=$client_secret&scope=$($query["scope"])&grant_type=authorization_code&access_type=offline"
    $strAccessToken = (Invoke-WebRequest -Uri "https://oauth2.googleapis.com/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing).Content 

    #$strAccessToken = (Invoke-WebRequest -Uri "https://www.googleapis.com/oauth2/v4/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing).Content
    $access_token = (ConvertFrom-Json $strAccessToken).access_token
    $refresh_token = (ConvertFrom-Json $strAccessToken).refresh_token
    $refresh_token | clip
    Set-SavedCredential -UserName $delegatedUser -Context $client_id -Prompt "Paste the Refresh Token from your clipboard" 
}

#endregion

#region Exchange Refresh Token for Access Token - needed every time

Write-Verbose "Exchanging Refresh Token for Access Token"
$headers = @{ 
    "Content-Type" = "application/x-www-form-urlencoded" 
 } 

$body = @{
    client_id     = $client_id
    client_secret = $client_secret
    refresh_token = $refresh_token
    grant_type    = 'refresh_token'
 }
 $params = @{
    'Uri'         = 'https://accounts.google.com/o/oauth2/token'
    'ContentType' = 'application/x-www-form-urlencoded'
    'Method'      = 'POST'
    'Headers'     = $headers
    'Body'        = $body
    'Verbose'     = $true
 }
 $accessTokenResponse = Invoke-RestMethod @params
 $access_token = $($accessTokenResponse.access_token)
 Write-Host "The access token contains the scopes $($accessTokenResponse.scope)"

#endregion

#region Get Matters

Write-Verbose "Calling the Google Vault API to list users on litigation hold"
   
Try{
        $Bearer = "Bearer " + $access_token
        $headers = @{ 
        "Content-Type" = "application/json; charset=utf-8" 
        "Authorization" = $Bearer
        }

        $params = @{
            'Uri'             = "https://vault.googleapis.com/v1/matters" 
            'ContentType'     = 'application/json'
            'Method'          = 'GET'
            'Headers'         = $headers
            'Verbose'         = $true
            'UseBasicParsing' = $true
        }

        $apiResponse = Invoke-WebRequest @params 
        $openmatters = ($apiResponse.Content | ConvertFrom-Json).matters | Where {$_.state -eq 'OPEN'}
        #$apiResponse

    }       
Catch{
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Verbose $ErrorMessage
            Write-Verbose $FailedItem
            $raiseJiraTicket = $true

} 

#endregion

#region Examine Matters and Holds

$matterhold = @()


If ($openmatters){      

        $matterhold = foreach ($matter in $openmatters){

            $baseURI = "https://vault.googleapis.com/v1/matters"
            $params.Uri = $baseURI + "/" + $matter.matterId + "/holds"   

            Write-Host "Calling $($params.Uri)"
            $apiResponse = Invoke-WebRequest @params

            [PSCustomObject]@{
                Matter = $matter.name
                MatterId = $matter.matterId
                Holds = ($apiResponse.Content | ConvertFrom-Json).holds
            }
        
        }

        If ($matterhold.holds.PSobject.BaseObject.accounts){

            $individualHolds = foreach ($m in $matterhold){
            
            If ($null -ne $m.Holds){              

                        [PSCustomObject]@{
                            AccountsID = ($m.holds).accounts.accountId
                            Email = ($m.holds).accounts.email
                            HoldTime = ($m.holds).accounts.holdTime
                            HoldConfig = 'Individual'
                        }

                    }

            }
        }

        If ($matterhold.holds.PSobject.BaseObject.orgUnit){

            $orgUnitHolds = foreach ($m in $matterhold){
            
            If ($null -ne $m.Holds){              

                        [PSCustomObject]@{
                            OrgUnitID = ($m.holds).orgUnit.orgUnitId
                            HoldTime = ($m.holds).orgUnit.holdTime
                            HoldConfig = 'OrgUnit'
                        }

                    }

            }
        }



        
}

#endregion

#region Examine OUs containing Holds
$orgUnitIdFinal  = @()
$orgUnitIdFinal = $orgUnitHolds.orgUnitId | Select-Object -Unique
Write-Host "Checking the OrgUnitPath for $($orgUnitIdFinal.count) OU based holds"

Foreach ($orgUnitId in $orgUnitIdFinal){

    <#

        These scopes are classified as sensative.

        https://www.googleapis.com/auth/admin.directory.orgunit.readonly is needed to call https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits/$OrgUnitId
        https://www.googleapis.com/auth/admin.directory.user.readonly is needed to call https://admin.googleapis.com/admin/directory/v1/users'
        https://www.googleapis.com/auth/admin.directory.orgunit.readonly is needed to call https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits"
    
        #>    

    # Get the OrgUnitPath using the OrgUnitId
    $orgUnitId = $orgUnitID
    $baseURI = "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits"
    $Bearer = "Bearer " + $access_token
    $headers = @{
        "Content-Type" = "application/json; charset=utf-8"
        "authorization" = $Bearer
    }

    $params = @{
        'Uri'             = $baseURI + "/" + $orgUnitId
        'ContentType'     = 'application/json'
        'Method'          = 'GET'
        'Headers'         = $headers
        'Verbose'         = $true
        'UseBasicParsing' = $true
    }

    $apiResponse = Invoke-WebRequest @params
    $orgUnitPath = ($apiResponse.content | ConvertFrom-Json).orgUnitPath
    
    Write-Host "Checking the OrgUnitPath '$orgUnitPath' for OU based holds"
    
    $encodedOrgUnitPath = [System.Web.HttpUtility]::UrlEncode("'$orgUnitPath'")    
    $domain = 'tripadvisor.com'
    # The query parameters must be URL-encoded
    $baseURI = "https://admin.googleapis.com/admin/directory/v1/users" 
    $Bearer = "Bearer " + $access_token
    $headers = @{ 
    "Content-Type" = "application/json; charset=utf-8" 
    "Authorization" = $Bearer
    }

    $ouHolds = @()
    Do {
        $params = @{
            'Uri'             = $baseURI + "?domain=$domain&query=orgUnitPath=$encodedOrgUnitPath&maxResults=500&pageToken=$(($apiresponse.content | ConvertFrom-Json).nextPageToken)"
            'ContentType'     = 'application/json'
            'Method'          = 'GET'
            'Headers'         = $headers
            'Verbose'         = $true
            'UseBasicParsing' = $true
        }

        Write-Host "Calling Google API"    
        $apiResponse = Invoke-WebRequest @params 

        $ouHolds += ($apiResponse.content | ConvertFrom-Json).users

        #$apiResponse
    } While (($apiresponse.content | ConvertFrom-Json).nextPageToken)

}

#endregion

$matterhold.count
$orgUnitHolds.count
$ouHolds.count
$individualHolds.count



Stop-Transcript
