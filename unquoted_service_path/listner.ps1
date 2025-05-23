$port = 4444
$listener = [System.Net.Sockets.TcpListener]::new($port)
$listener.Start()
Write-Host "[*] Listening on port $port..."

$client = $listener.AcceptTcpClient()
Write-Host "[*] Connection received from $($client.Client.RemoteEndPoint)"

$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
$writer.AutoFlush = $true

while ($true) {
    $input = $reader.ReadLine()
    if ($input -ne $null) {
        Write-Host "[Shell] $input"
    }
}