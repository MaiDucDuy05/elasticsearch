$ES = "http://localhost:9200"
$headers = @{ "Content-Type" = "application/json" }

Write-Host ">>> Tao ILM policy..."
Invoke-RestMethod -Method PUT "$ES/_ilm/policy/siem-ilm-policy" `
  -Headers $headers `
  -Body (Get-Content ilm/siem-ilm-policy.json -Raw)

Write-Host ">>> Tao template zeek-conn..."
Invoke-RestMethod -Method PUT "$ES/_index_template/zeek-conn-template" `
  -Headers $headers `
  -Body (Get-Content templates/zeek-conn-template.json -Raw)

Write-Host ">>> Tao template snort-alert..."
Invoke-RestMethod -Method PUT "$ES/_index_template/snort-alert-template" `
  -Headers $headers `
  -Body (Get-Content templates/snort-alert-template.json -Raw)

Write-Host ">>> Tao write index zeek-conn-000001..."
Invoke-RestMethod -Method PUT "$ES/zeek-conn-000001" `
  -Headers $headers `
  -Body '{"aliases":{"zeek-conn":{"is_write_index":true}}}'

Write-Host ">>> Tao write index snort-alert-000001..."
Invoke-RestMethod -Method PUT "$ES/snort-alert-000001" `
  -Headers $headers `
  -Body '{"aliases":{"snort-alert":{"is_write_index":true}}}'

Write-Host ">>> Done!"