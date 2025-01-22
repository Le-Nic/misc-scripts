# Define input and output folders
$inputFolder = "input"
$outputFolder = "output"

# Ensure output folder exists
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# Define service-specific scan configurations
$serviceScanConfigs = @{
    "ssh" = @{
        Condition = { param($port, $service) $port -eq 22 -or $service -eq "ssh" }
        ScanType = "ssh"
        NmapScript = "ssh-auth-methods,ssh2-enum-algos"
    }
    "ssl" = @{
        Condition = { param($port, $service) $service -match "ssl|https" }
        ScanType = "ssl"
        NmapScript = "ssl-enum-ciphers,ssl-cert"
    }
    "smb" = @{
        Condition = { param($port, $service) $port -in @(139, 445) -or $service -match "smb|msrpc|netbios|microsoft-ds" }
        ScanType = "smb"
        NmapScript = "smb* and safe"
    }
    "rdp" = @{
        Condition = { param($port, $service) $port -in @(3389) -or $service -match "rdp|ms-wbt-server" }
        ScanType = "rdp"
        NmapScript = "rdp* and safe"
    }
    "dns" = @{
        Condition = { param($port, $service) $port -in @(53) -or $service -match "dns" }
        ScanType = "dns"
        NmapScript = "dns* and safe"
    }
    "http" = @{
        Condition = { param($port, $service) $service -match "http|https" }
        ScanType = "http"
        NmapScript = "http* and safe"
    }
    "ftp" = @{
        Condition = { param($port, $service) $service -match "ftp" }
        ScanType = "ftp"
        NmapScript = "ftp* and safe"
    }
    "smtp" = @{
        Condition = { param($port, $service) $service -match "smtp" }
        ScanType = "smtp"
        NmapScript = "smtp* and safe"
    }
    "ntp" = @{
        Condition = { param($port, $service) $service -match "ntp" }
        ScanType = "ntp"
        NmapScript = "ntp* and safe"
    }
    "telnet" = @{
        Condition = { param($port, $service) $service -match "telnet" }
        ScanType = "telnet"
        NmapScript = "telnet* and safe"
    }
    "snmp" = @{
        Condition = { param($port, $service) $service -match "snmp" }
        ScanType = "snmp"
        NmapScript = "snmp* and safe"
    }
    # Add more service configurations here
}

# Function to parse Nmap XML output
function Parse-NmapXML($xmlPath) {
    [xml]$xml = Get-Content $xmlPath
    $items = $xml.nmaprun.host
    $results = @()
    foreach ($item in $items) {
        $ip = $item.address.addr
        $ports = $item.ports.port
        $portStatuses = @{}
        foreach ($port in $ports) {
            $portStatuses[$port.portid] = $port.state.state
        }
        $results += [PSCustomObject]@{
            IP = $ip
            PortStatuses = $portStatuses
            Services = $ports | ForEach-Object { 
                [PSCustomObject]@{
                    Port = $_.portid
                    Service = $_.service.name
                    State = $_.state.state
                }
            }
        }
    }
    return $results
}

# Function to perform service-specific scans
function Perform-ServiceSpecificScans($ip, $fileBaseName, $result) {
    foreach ($config in $serviceScanConfigs.Values) {
        $matchingServices = $result.Services | Where-Object { 
            $config.Condition.Invoke($_.Port, $_.Service) 
        }
        
        if ($matchingServices) {
            $scanType = $config.ScanType
            $ip = $ip -replace '[^\w\-]', '-'
            $outputName = "${ip}_${scanType}"
            $outputPath = Join-Path -Path $outputFolder -ChildPath $fileBaseName | Join-Path -ChildPath $outputName
            $portList = ($matchingServices.Port | Sort-Object -Unique) -join ","
            $nmapCommand = "nmap -Pn -p $portList --script '$($config.NmapScript)' -oA `"$outputPath`" $ip"
            Write-Host "`nPerforming $scanType on $ip" -ForegroundColor Green
            Invoke-Expression $nmapCommand
        }
    }
}

# Function to perform ping
function Perform-Ping($ip) {
    $pingResult = Test-Connection -ComputerName $ip -Count 1 -Quiet
    return $pingResult
}

# Get all text files in the input folder
$inputFiles = Get-ChildItem -Path $inputFolder -Filter "*.txt"

# Perform discovery scan for all IPs/domains
$discoveryResults = @()
foreach ($file in $inputFiles) {
    $scanType = "discovery"
    $fileBaseName = $file.BaseName
    
    if (-not (Test-Path -Path (Join-Path -Path $outputFolder -ChildPath $fileBaseName))) {
        New-Item -ItemType Directory -Path (Join-Path -Path $outputFolder -ChildPath $fileBaseName) | Out-Null
    }

    Write-Host "`nPerforming discovery scan for $fileBaseName" -ForegroundColor Green
    
    $ips = Get-Content $file.FullName
    foreach ($ip in $ips) {
        $ip = $ip -replace '[^\w\-]', '-'
        $outputName = "${ip}_${scanType}"
        $outputPath = Join-Path -Path $outputFolder -ChildPath $fileBaseName | Join-Path -ChildPath $outputName
        
        # Perform ping
        $pingStatus = Perform-Ping $ip

        $nmapCommand = "nmap -Pn -p 22,135,139,445 -oA `"$outputPath`" $ip"
        Invoke-Expression $nmapCommand
        
        $xmlPath = "$outputPath.xml"
        $nmapResults  = Parse-NmapXML $xmlPath

        foreach ($result in $nmapResults) {
            $discoveryResults += [PSCustomObject]@{
                IP = $result.IP
                PingStatus = $pingStatus
                PortStatuses = $result.PortStatuses
                Services = $result.Services
            }
        }
    }
}

# Print out the status of all IPs
foreach ($result in $discoveryResults) {
    
    $pingStatus = if ($result.PingStatus) { "Responsive" } else { "Unresponsive" }
    $portStatusSummary = $result.PortStatuses.Values | Group-Object | ForEach-Object { "$($_.Name): $($_.Count)" }
    $portStatusString = $portStatusSummary -join ', '
    Write-Host "`n[$($result.IP)] Ping: $pingStatus, Ports: $portStatusString" -ForegroundColor Green
    foreach ($port in $result.PortStatuses.Keys | Sort-Object) {
        Write-Host "> Port $($port): $($result.PortStatuses[$port])" -ForegroundColor Green
    }
}

# Perform detailed scans for each IP/domain
foreach ($file in $inputFiles) {
    $fileBaseName = $file.BaseName
    $ips = Get-Content $file.FullName
    
    foreach ($ip in $ips) {
        $ip = $ip -replace '[^\w\-]', '-'
        
        # Full TCP scan
        $outputName = "${ip}_tcp"
        $outputPath = Join-Path -Path $outputFolder -ChildPath $fileBaseName | Join-Path -ChildPath $outputName
        $nmapCommand = "nmap -v -Pn -sV -p- -oA `"$outputPath`" $ip"
        Write-Host "`n! Performing tcp-scan on $ip" -ForegroundColor Green
        Invoke-Expression $nmapCommand
        
        # UDP scan
        $outputName = "${ip}_udp"
        $outputPath = Join-Path -Path $outputFolder -ChildPath $fileBaseName | Join-Path -ChildPath $outputName
        $nmapCommand = "nmap -v -Pn -sU --open --max-retries 0 -oA `"$outputPath`" $ip"
        Write-Host "`n! Performing udp-scan on $ip" -ForegroundColor Green
        Invoke-Expression $nmapCommand
        
        # Parse results for additional scans
        $tcpXmlPath = Join-Path -Path $outputFolder -ChildPath $fileBaseName | Join-Path -ChildPath "${ip}_tcp-scan.xml"
        $tcpResults = Parse-NmapXML $tcpXmlPath
        
        foreach ($result in $tcpResults) {
            Perform-ServiceSpecificScans $ip $fileBaseName $result
        }
    }
}

Write-Host "`nAll scans completed. Results are saved in $outputFolder" -ForegroundColor Green
