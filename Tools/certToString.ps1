<#
  Convert cert with base-64 to c string
#>

if($args.Length -ne 1){
    Write-Warning "Usage: certToString.ps1 <.cer file name>"
    Exit -1
}

$cert = Get-Content $args[0]
$length = $cert.Length
$loopLength = $length - 1
for($i = 0; $i -lt $loopLength; $i++){
    $cert[$i] = "`"$($cert[$i])\r\n`" \"
}
$cert[$length - 1] = "`"$($cert[$length - 1])\r\n`""

Set-Content  "$($args[0]).txt" $cert
