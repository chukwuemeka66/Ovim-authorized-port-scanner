$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:SPLUNK_HEC_URL)) {
    throw 'Set SPLUNK_HEC_URL before running this script.'
}
if ([string]::IsNullOrWhiteSpace($env:SPLUNK_HEC_TOKEN)) {
    throw 'Set SPLUNK_HEC_TOKEN before running this script.'
}

$secureKey = Read-Host 'NodeZero API Key' -AsSecureString
$bstr = [IntPtr]::Zero
$hadPreviousApiKey = Test-Path Env:H3_API_KEY
$previousApiKey = $env:H3_API_KEY
$exitCode = 0

try {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $env:H3_API_KEY = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    & go run . -nodezero-to-splunk
    $exitCode = $LASTEXITCODE
}
finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $secureKey.Dispose()
    if ($hadPreviousApiKey) {
        $env:H3_API_KEY = $previousApiKey
    }
    else {
        Remove-Item Env:H3_API_KEY -ErrorAction SilentlyContinue
    }
}

exit $exitCode