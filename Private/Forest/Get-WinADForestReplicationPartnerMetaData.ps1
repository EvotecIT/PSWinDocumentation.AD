function Get-WinADForestReplicationPartnerMetaData {
    [CmdletBinding()]
    param(
        [switch] $Extended
    )
    $Replication = Get-ADReplicationPartnerMetadata -Target * -Partition *
    foreach ($_ in $Replication) {
        $ServerPartner = (Resolve-DnsName -Name $_.PartnerAddress -Verbose:$false)
        $ServerInitiating = (Resolve-DnsName -Name $_.Server -Verbose:$false)
        $ReplicationObject = [ordered] @{
            Server                         = $_.Server
            ServerIPV4 = $ServerInitiating.IP4Address
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
}