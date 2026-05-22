<#
.SYNOPSIS
    Uninstalls filebeat Windows service.
#>

# Delete and stop the service if it already exists.
if (Get-Service filebeat -ErrorAction SilentlyContinue) {
  Stop-Service filebeat
  (Get-Service filebeat).WaitForStatus('Stopped')
  Start-Sleep -s 1
  sc.exe delete filebeat
}
