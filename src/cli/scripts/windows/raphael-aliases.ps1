Set-StrictMode -Version Latest

function Test-RaphaelCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Assert-RaphaelCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [string]$InstallHint
  )

  if (-not (Test-RaphaelCommand -Name $Name)) {
    throw "Required command '$Name' was not found. $InstallHint"
  }
}

function Invoke-Raphael {
  [CmdletBinding()]
  param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RaphaelArgs
  )

  Assert-RaphaelCommand -Name "raphael" -InstallHint "Install with: npm install -g raphael"

  & raphael @RaphaelArgs

  if ($LASTEXITCODE -ne 0) {
    throw "raphael failed with exit code $LASTEXITCODE."
  }
}

function Invoke-RaphaelWithEnvironment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$Environment,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RaphaelArgs
  )

  $previousValues = @{}

  foreach ($name in $Environment.Keys) {
    $previousValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    Set-Item -Path "Env:$name" -Value $Environment[$name]
  }

  try {
    Invoke-Raphael @RaphaelArgs
  }
  finally {
    foreach ($name in $Environment.Keys) {
      if ($null -eq $previousValues[$name]) {
        Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
      }
      else {
        Set-Item -Path "Env:$name" -Value $previousValues[$name]
      }
    }
  }
}

function Get-RaphaelQuickHelp {
  [CmdletBinding()]
  param()

  @(
    "Raphael quick commands:",
    "  rc [args...]              -> launch Raphael using the installed CLI",
    "  rc-local [args...]        -> launch Raphael with local/Ollama OpenAI-compatible environment hints for this invocation only",
    "  rc-fast [args...]         -> launch Raphael with low-latency local defaults for this invocation only",
    "  rc-provider               -> open the provider manager in Raphael",
    "  rc-check                  -> show Ollama install/listening/model state",
    "  rc-init                   -> pull/check the local model, then launch local/Ollama mode",
    "  rc-help                   -> show this help"
  ) -join [Environment]::NewLine
}

function rc {
  [CmdletBinding()]
  param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RaphaelArgs
  )

  Invoke-Raphael @RaphaelArgs
}

function rc-local {
  [CmdletBinding()]
  param(
    [string]$Model = "llama3.1:8b",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RaphaelArgs
  )

  Invoke-RaphaelWithEnvironment `
    -Environment @{
      CLAUDE_CODE_USE_OPENAI = "1"
      OPENAI_BASE_URL        = "http://localhost:11434/v1"
      OPENAI_MODEL           = $Model
    } `
    @RaphaelArgs
}

function rc-fast {
  [CmdletBinding()]
  param(
    [string]$Model = "llama3.1:8b",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RaphaelArgs
  )

  Invoke-RaphaelWithEnvironment `
    -Environment @{
      CLAUDE_CODE_USE_OPENAI = "1"
      OPENAI_BASE_URL        = "http://localhost:11434/v1"
      OPENAI_MODEL           = $Model
      OPENCLAUDE_FAST_MODE   = "1"
    } `
    @RaphaelArgs
}

function rc-provider {
  [CmdletBinding()]
  param()

  Invoke-Raphael "/provider"
}

function rc-check {
  [CmdletBinding()]
  param(
    [string]$Model = "llama3.1:8b"
  )

  Assert-RaphaelCommand -Name "ollama" -InstallHint "Install Ollama from https://ollama.com/download/windows."

  $version = & ollama --version 2>$null
  $modelNames = (& ollama list 2>$null | Select-Object -Skip 1 | ForEach-Object {
      ($_ -split "\s+")[0]
    }) | Where-Object { $_ }

  $isModelAvailable = $modelNames -contains $Model
  $probeSucceeded = $false

  try {
    $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 3
    if ($response.models) {
      $probeSucceeded = $true
    }
  }
  catch {
    $probeSucceeded = $false
  }

  [PSCustomObject]@{
    OllamaInstalled = $true
    OllamaVersion   = $version
    OllamaListening = $probeSucceeded
    Model           = $Model
    ModelAvailable  = $isModelAvailable
  }
}

function rc-init {
  [CmdletBinding()]
  param(
    [string]$Model = "llama3.1:8b",
    [switch]$SkipModelPull
  )

  Assert-RaphaelCommand -Name "ollama" -InstallHint "Install Ollama from https://ollama.com/download/windows."

  if (-not $SkipModelPull) {
    & ollama pull $Model
    if ($LASTEXITCODE -ne 0) {
      throw "ollama pull $Model failed with exit code $LASTEXITCODE."
    }
  }

  $health = rc-check -Model $Model
  if (-not $health.OllamaListening) {
    Write-Warning "Ollama is installed but API probe to localhost:11434 did not succeed. Start Ollama and retry."
  }

  rc-local -Model $Model
}

function rc-help {
  [CmdletBinding()]
  param()

  Get-RaphaelQuickHelp
}
