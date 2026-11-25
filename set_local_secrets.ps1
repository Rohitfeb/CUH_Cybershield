$ErrorActionPreference = "Stop"

$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envPath)) {
    throw ".env not found. Copy .env.example to .env first."
}

$databaseUrl = Read-Host "Enter the Neon PostgreSQL DATABASE_URL"
$appPassword = Read-Host "Enter the Gmail app password" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($appPassword)
try {
    $appPasswordText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if (-not $databaseUrl.StartsWith("postgresql")) {
    throw "DATABASE_URL must be a PostgreSQL connection URL."
}
if ([string]::IsNullOrWhiteSpace($appPasswordText)) {
    throw "Gmail app password cannot be empty."
}

$lines = Get-Content $envPath
$updated = foreach ($line in $lines) {
    if ($line.StartsWith("DATABASE_URL=")) {
        "DATABASE_URL=$databaseUrl"
    }
    elseif ($line.StartsWith("MAIL_PASSWORD=")) {
        "MAIL_PASSWORD=$appPasswordText"
    }
    else {
        $line
    }
}

Set-Content -Path $envPath -Value $updated
$appPasswordText = ""

Write-Host "Local .env secrets updated. The file is ignored by Git."
