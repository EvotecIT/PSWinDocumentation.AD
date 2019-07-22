﻿function Get-WinADForestReplicationPartnerMetaData {
    [CmdletBinding()]
    param(
        [switch] $Extended
    )
    $Replication = Get-ADReplicationPartnerMetadata -Target * -Partition * -ErrorAction SilentlyContinue -ErrorVariable ProcessErrors
    if ($ProcessErrors) {
        foreach ($_ in $ProcessErrors) {
            Write-Warning -Message "Get-WinADForestReplicationPartnerMetaData - Error on server $($_.Exception.ServerName): $($_.Exception.Message)"
        }
    }
    foreach ($_ in $Replication) {
        $ServerPartner = (Resolve-DnsName -Name $_.PartnerAddress -Verbose:$false -ErrorAction SilentlyContinue)
        $ServerInitiating = (Resolve-DnsName -Name $_.Server -Verbose:$false -ErrorAction SilentlyContinue)
        $ReplicationObject = [ordered] @{
            Server                         = $_.Server
            ServerIPV4                     = $ServerInitiating.IP4Address
            ServerPartner                  = $ServerPartner.NameHost
            ServerPartnerIPV4              = $ServerPartner.IP4Address
            LastReplicationAttempt         = $_.LastReplicationAttempt
            LastReplicationResult          = $_.LastReplicationResult
            LastReplicationSuccess         = $_.LastReplicationSuccess
            ConsecutiveReplicationFailures = $_.ConsecutiveReplicationFailures
            LastChangeUsn                  = $_.LastChangeUsn
            PartnerType                    = $_.PartnerType

            Partition                      = $_.Partition
            TwoWaySync                     = $_.TwoWaySync
            ScheduledSync                  = $_.ScheduledSync
            SyncOnStartup                  = $_.SyncOnStartup
            CompressChanges                = $_.CompressChanges
            DisableScheduledSync           = $_.DisableScheduledSync
            IgnoreChangeNotifications      = $_.IgnoreChangeNotifications
            IntersiteTransport             = $_.IntersiteTransport
            IntersiteTransportGuid         = $_.IntersiteTransportGuid
            IntersiteTransportType         = $_.IntersiteTransportType

            UsnFilter                      = $_.UsnFilter
            Writable                       = $_.Writable
            Status                         = if ($_.LastReplicationResult -ne 0) { $false } else { $true }
            StatusMessage                  = "Last successful replication time was $($_.LastReplicationSuccess), Consecutive Failures: $($_.ConsecutiveReplicationFailures)"
        }
        if ($Extended) {
            $ReplicationObject.Partner = $_.Partner
            $ReplicationObject.PartnerAddress = $_.PartnerAddress
            $ReplicationObject.PartnerGuid = $_.PartnerGuid
            $ReplicationObject.PartnerInvocationId = $_.PartnerInvocationId
            $ReplicationObject.PartitionGuid = $_.PartitionGuid
        }
        [PSCustomObject] $ReplicationObject
    }
    foreach ($_ in $ProcessErrors) {
        $ServerInitiating = (Resolve-DnsName -Name $_.Exception.ServerName -Verbose:$false -ErrorAction SilentlyContinue)
        $ReplicationObject = [ordered] @{
            Server                         = $_.Exception.ServerName
            ServerIPV4                     = $ServerInitiating.IP4Address
            ServerPartner                  = 'Unknown'
            ServerPartnerIPV4              = '127.0.0.1'
            LastReplicationAttempt         = $null
            LastReplicationResult          = $null
            LastReplicationSuccess         = $null
            ConsecutiveReplicationFailures = $null
            LastChangeUsn                  = $null
            PartnerType                    = $null

            Partition                      = $null
            TwoWaySync                     = $null
            ScheduledSync                  = $null
            SyncOnStartup                  = $null
            CompressChanges                = $null
            DisableScheduledSync           = $null
            IgnoreChangeNotifications      = $null
            IntersiteTransport             = $null
            IntersiteTransportGuid         = $null
            IntersiteTransportType         = $null

            UsnFilter                      = $null
            Writable                       = $null
            Status                         = $false
            StatusMessage                  = $_.Exception.Message
        }
        if ($Extended) {
            $ReplicationObject.Partner = $null
            $ReplicationObject.PartnerAddress = $null
            $ReplicationObject.PartnerGuid = $null
            $ReplicationObject.PartnerInvocationId = $null
            $ReplicationObject.PartitionGuid = $null
        }
        [PSCustomObject] $ReplicationObject
    }
}