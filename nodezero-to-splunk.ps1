$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:SPLUNK_HEC_URL)) {
    throw 'Set SPLUNK_HEC_URL before running this script.'
}

$secureKey = Read-Host 'NodeZero API Key' -AsSecureString
$bstr = [IntPtr]::Zero
$secureHecToken = $null
$hecTokenBstr = [IntPtr]::Zero
$hadPreviousApiKey = Test-Path Env:H3_API_KEY
$previousApiKey = $env:H3_API_KEY
$hadPreviousHecToken = Test-Path Env:SPLUNK_HEC_TOKEN
$previousHecToken = $env:SPLUNK_HEC_TOKEN
$exitCode = 0

try {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $env:H3_API_KEY = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($env:SPLUNK_HEC_TOKEN)) {
        $secureHecToken = Read-Host 'Splunk HEC Token' -AsSecureString
        $hecTokenBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureHecToken)
        $env:SPLUNK_HEC_TOKEN = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($hecTokenBstr)
    }
    & go run . -nodezero-to-splunk
    $exitCode = $LASTEXITCODE
}
finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ($hecTokenBstr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($hecTokenBstr)
    }
    $secureKey.Dispose()
    if ($null -ne $secureHecToken) {
        $secureHecToken.Dispose()
    }
    if ($hadPreviousApiKey) {
        $env:H3_API_KEY = $previousApiKey
    }
    else {
        Remove-Item Env:H3_API_KEY -ErrorAction SilentlyContinue
    }
    if ($hadPreviousHecToken) {
        $env:SPLUNK_HEC_TOKEN = $previousHecToken
    }
    else {
        Remove-Item Env:SPLUNK_HEC_TOKEN -ErrorAction SilentlyContinue
    }
}

exit $exitCode