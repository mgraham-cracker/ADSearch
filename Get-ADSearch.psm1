function Get-ADSearch
{
 <#
    .SYNOPSIS
        Search Active Directory for Users and or Groups. User searches traverse up the tree for parents.
        Group searches can traverse both up and down the Active Directory tree finding parents and children.

    .DESCRIPTION
        Search Active Directory for Users and or Groups. User searches traverse up the tree for parents.
        Group searches can traverse both up and down the Active Directory tree finding parents and children.

        Note: The search will always return the root element in the list if found

        Install into the Modules folder for direct access without the need for dot sourcing
        To determine current environment module search paths execute this command:
        $env:PSModulePath

        For more details, see the accompanying blog post:
            http://github.com/mgraham-cracker/ADSearch

    .PARAMETER AccountName
        'AccountName' [string]  You can use the pipeline for AccountName input.

        The search text allows for use of asterisk wildcards anywhere in the string.
        Example: Get-AdSearch -AccountName "Al*"

        #This search locates any user or group having a SamAccountName beginning with Al.

        If the name relates to a user then an upward tree search will be recursively performed.
        If the name relates to a group then both upward and downward tree searches are available.
        
    .PARAMETER GroupSearchMethod
        'GroupSearchMethod' [string] Values allowed "all" (search up and down) or "membersonly" (search down) or "membersofonly" (search up).
        
        "membersofonly" is the default value if not defined. 

        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "membersonly"

        #This search locates any user or group called Admins and only searches down the tree
        Admins
        Admins<-Smith
        Admins<-Dev-Admins
        Admins<-Dev-Admins<-John
        Admins<-Dev-Admins<-Bob

        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "membersofonly"

        #This search locates any user or group called Admins and only searches up the tree
        Admins
        Admins->US-Admins
        Admins->US-Admins<-Global-Admins

        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "all"

        #This search locates any user or group called Admins and searches down the tree
        #for users and groups and up the tree only for groups
        Admins
        Admins<-Smith
        Admins<-Dev-Admins
        Admins<-Dev-Admins<-John
        Admins<-Dev-Admins<-Bob
        Admins->US-Admins
        Admins->US-Admins<-Global-Admins
        
    .PARAMETER DomainServer
        'DomainServer' [string]

        The default value is obtained from (Get-ADDomain -Current LocalComputer).DNSRoot if not specified

        Note: If you have multiple domain trust the search be aware that the relationship search will navigate down permission trees
        in other domains if users or groups from those other domains are related to users or groups within your search domain.
        That is to say the search uses the full distinguised name for parent and children searches.

        .PARAMETER MemberSearchExclude
        'MemberSearchExclude' [string] Values allowed "none" (list users and groups) or "users" (exclude users) or "membersofonly" (exclude groups).
        
        "none" is the default value if not defined. 

        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "membersonly" -MemberSearchExclude "users"

        #This search locates any user or group called Admins and only searches down the tree.
        #If the root account is a group only groups will be listed. If the root account is a user only itself will be listed
        Admins
        Admins<-Dev-Admins


        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "membersofonly" -MemberSearchExclude "groups"

        #This search locates any user or group called Admins and only searches up the tree.
        #Because the GroupSearchMethod parameter is limiting an upward search the MemberSearchExclude is ignored.
        Admins
        Admins->US-Admins
        Admins->US-Admins<-Global-Admins

        Example: Get-AdSearch -AccountName "Admins" -GroupSearchMethod "all" -MemberSearchExclude "none"

        #This search locates any user or group called Admins and searches down the tree
        #for users and groups and up the tree only for groups
        Admins
        Admins<-Smith
        Admins<-Dev-Admins
        Admins<-Dev-Admins<-John
        Admins<-Dev-Admins<-Bob
        Admins->US-Admins
        Admins->US-Admins<-Global-Admins

    .PARAMETER JoinType
        'JoinType' [string]  Values allowed "left", "right", "inner"

        This parameter is used dependent on the JoinAccountName parameter being specified.

        "left" = Return all groups AccountName is a member of and only matching groups that JoinAccountName are a member of
        "right" = Return all groups JoinAccountName are a member of and only matching groups that AccountName are a member of
        "inner" = Return only members of groups that match between JoinAccountName and AccountName
        "full" = Return all members of groups from JoinAccountName and AccountName whether they match or not

    .PARAMETER JoinAccountName
        'JoinAccountName' [string] 

        This parameter is used dependent on the JoinType parameter being specified.
        It is recommended to not use wildcards when trying to use the join parameters.
        This value will be used to search SamAccountName values in the active directory

    .PARAMETER JoinDistinct
        'JoinDistinct' [string]  Values allowed "true" [default] or "false"

        This parameter is used to limit the comparison sets to unique list by excluding the Comment field.
        The comment field list the inheritance path giving the accounts permissions. If wish to see the inheritance path
        you will need to set this value to false.

    .PARAMETER Output
        'Output' [string] Values allowed are "grid" or "pipeline"

        The default value is grid which is intended for interactive use

        Note: Data in the output grid can be copied to the clipboard, filtered, and columns rearranged.

    .PARAMETER Mode
        'Mode' [string] Values allowed are "speed" or "robust"

        The default value is speed which is intended to perform a quick memberof search for a user. This feature presumes you do
        not wish to perform comparison or multi-direction searches

        Note: If you specify a value for JoinAccountName then the mode will be overridden to robust
    

    .FUNCTIONALITY
        Active Directory Utility

    #>
    [CmdletBinding()]
    param (
    [Parameter(ValuefromPipeline=$true,mandatory=$true,Position=0
        ,HelpMessage="Supply an AD User or Group Name.")][String] $AccountName,
    [Parameter(mandatory=$false,Position=1
        ,HelpMessage="all, membersonly, membersofonly [default]")][String][ValidateSet("all", "membersonly", "membersofonly")]  $GroupSearchMethod = "membersofonly",
    [Parameter(mandatory=$false,Position=2)][String] $DomainServer = 
        (Get-ADDomain -Current LocalComputer).DNSRoot,
    [Parameter(mandatory=$false,Position=3
        ,HelpMessage="users, groups, none [default]")][String][ValidateSet("none", "groups", "users")]  $MemberSearchExclude = "none",
    [Parameter(mandatory=$false,Position=4
        ,HelpMessage="left, right, inner, full [default]")][String][ValidateSet("left", "right", "inner", "full")]  $JoinType = "full",
    [Parameter(mandatory=$false,Position=5
        ,HelpMessage="Supply an AD User or Group Name.")][String] $JoinAccountName,
    [Parameter(mandatory=$false,Position=6
        ,HelpMessage="true [default], false")][String][ValidateSet("true", "false")]  $JoinDistinct = "true",
    [Parameter(mandatory=$false,Position=7
        ,HelpMessage="grid [Default], pipeline")][String][ValidateSet("grid", "pipeline")]  $Output = "grid",
    [Parameter(mandatory=$false,Position=8
        ,HelpMessage="speed [Default], robust")][String][ValidateSet("speed", "robust")]  $Mode = "speed"
    )
    
    if($Mode -eq "robust" -or $JoinAccountName)
    {
        $stime=(Get-Date)
        $AccountList = Get-ADMembershipList -AccountName $AccountName -DomainServer $DomainServer -GroupSearchMethod $GroupSearchMethod -MemberSearchExclude $MemberSearchExclude
        $etime=(Get-Date)
        Write-Verbose "$($etime-$stime) AccountName Search Completed"

        if($JoinAccountName)
        {
        $stime=(Get-Date)
            $JoinAccountList = Get-ADMembershipList -AccountName $JoinAccountName -DomainServer $DomainServer -GroupSearchMethod $GroupSearchMethod -MemberSearchExclude $MemberSearchExclude
            $etime=(Get-Date)
            Write-Verbose "$($etime-$stime) JoinAccountName Search Completed"
            #Limit Columns helpful to comparison columns
            if($JoinDistinct -eq "true")
            {
            $stime=(Get-Date)
                $JoinAccountList = $JoinAccountList | 
                    Select ObjectClass, DNSRoot, SamAccountName, DN, RootSamAccountName, SID -Unique
                    $etime=(Get-Date)
                    Write-Verbose "$($etime-$stime) AccountName Unique Filter Completed"

            $stime=(Get-Date)
                $AccountList = $AccountList | 
                    Select ObjectClass, DNSRoot, SamAccountName, DN, RootSamAccountName, SID -Unique
                    $etime=(Get-Date)
                    Write-Verbose "$($etime-$stime) JoinAccountName Unique Filter Completed"
            }
            else
            {
                $JoinAccountList = $JoinAccountList | 
                    Select ObjectClass, DNSRoot, SamAccountName, Comment, DN, RootSamAccountName, SID

                $AccountList = $AccountList | 
                    Select ObjectClass, DNSRoot, SamAccountName, Comment, DN, RootSamAccountName, SID
            }
            $stime=(Get-Date)
            $Compare_AccountList = Compare-Object -ReferenceObject $AccountList -DifferenceObject $JoinAccountList -IncludeEqual -Property SID -PassThru
            $etime=(Get-Date)
            Write-Verbose "$($etime-$stime) Compare Completed"

            $Join_AccountList=@()

            if($JoinType -eq "right" -or $JoinType -eq "full")
            {
            $stime=(Get-Date)
                $Join_AccountList += $Compare_AccountList | Where-Object {$_.SideIndicator -eq "=>"} |
                    Select @{Name="Account_ObjectClass";Expression={$null}}, `
                    @{Name="Account_DNSRoot";Expression={$null}}, `
                    @{Name="Account_RootSamAccountName";Expression={$null}}, `
                    @{Name="Account_SamAccountName";Expression={$null}}, `
                    @{Name="JoinAccount_ObjectClass";Expression={$_.ObjectClass}}, `
                    @{Name="JoinAccount_SamAccountName";Expression={$_.SamAccountName}}, `
                    @{Name="Account_Comment";Expression={$null}}, `
                    @{Name="JoinAccount_Comment";Expression={$_.Comment}}, `
                    @{Name="Account_DN";Expression={$null}}, `
                    @{Name="Account_SID";Expression={$null}}, `
                    @{Name="JoinAccount_DN";Expression={$_.DN}}, `
                    @{Name="JoinAccount_DNSRoot";Expression={$_.DNSRoot}}, `
                    @{Name="JoinAccount_RootSamAccountName";Expression={$_.RootSamAccountName}}, `
                    @{Name="JoinAccount_SID";Expression={$_.SID}}
                    $etime=(Get-Date)
                    Write-Verbose "$($etime-$stime) Right Join Output Completed"
            }
            if($JoinType -eq "left" -or $JoinType -eq "full")
            {
            $stime=(Get-Date)
                $Join_AccountList += $Compare_AccountList | Where-Object {$_.SideIndicator -eq "<="} |
                    Select @{Name="Account_ObjectClass";Expression={$_.ObjectClass}}, `
                    @{Name="Account_DNSRoot";Expression={$_.DNSRoot}}, `
                    @{Name="Account_RootSamAccountName";Expression={$_.RootSamAccountName}}, `
                    @{Name="Account_SamAccountName";Expression={$_.SamAccountName}}, `
                    @{Name="JoinAccount_ObjectClass";Expression={$null}}, `
                    @{Name="JoinAccount_SamAccountName";Expression={$null}}, `
                    @{Name="Account_Comment";Expression={$_.Comment}}, `
                    @{Name="JoinAccount_Comment";Expression={$null}}, `
                    @{Name="Account_DN";Expression={$_.DN}}, `
                    @{Name="Account_SID";Expression={$_.SID}}, `
                    @{Name="JoinAccount_DN";Expression={$null}}, `
                    @{Name="JoinAccount_DNSRoot";Expression={$null}}, `
                    @{Name="JoinAccount_RootSamAccountName";Expression={$null}}, `
                    @{Name="JoinAccount_SID";Expression={$null}}
                    $etime=(Get-Date)
                    Write-Verbose "$($etime-$stime) Left Join Output Completed"
            }
            $stime=(Get-Date)
            foreach($AccountMatch in $($Compare_AccountList | Where-Object {$_.SideIndicator -eq "=="}))
            {
                $Accounts = $AccountList | Where-Object {$_.SID -eq $AccountMatch.SID}
                $JoinAccounts = $JoinAccountList | Where-Object {$_.SID -eq $AccountMatch.SID}
                foreach($Account in $Accounts)
                {
                    foreach($JoinAccount in $JoinAccounts)
                    {
                        $Join_AccountList += $Account | 
                        Select @{Name="Account_ObjectClass";Expression={$_.ObjectClass}}, `
                        @{Name="Account_DNSRoot";Expression={$_.DNSRoot}}, `
                        @{Name="Account_RootSamAccountName";Expression={$_.RootSamAccountName}}, `
                        @{Name="Account_SamAccountName";Expression={$_.SamAccountName}}, `
                        @{Name="JoinAccount_ObjectClass";Expression={$JoinAccount.ObjectClass}}, `
                        @{Name="JoinAccount_SamAccountName";Expression={$JoinAccount.SamAccountName}}, `
                        @{Name="Account_Comment";Expression={$_.Comment}}, `
                        @{Name="JoinAccount_Comment";Expression={$JoinAccount.Comment}}, `
                        @{Name="Account_DN";Expression={$_.DN}}, `
                        @{Name="Account_SID";Expression={$_.SID}}, `
                        @{Name="JoinAccount_DN";Expression={$JoinAccount.DN}}, `                        
                        @{Name="JoinAccount_DNSRoot";Expression={$JoinAccount.DNSRoot}}, `
                        @{Name="JoinAccount_RootSamAccountName";Expression={$JoinAccount.RootSamAccountName}}, `
                        @{Name="JoinAccount_SID";Expression={$JoinAccount.SID}}
                    }
                }
            }
            $etime=(Get-Date)
            Write-Verbose "$($etime-$stime) Equality Join Output Completed"
        
            $AccountList = $Join_AccountList
                   
        }
    }
    else
    {
        $AccountList = Get-UserGroupQuick $AccountName
    }
   
     
    if($Output -eq "grid")
    {
        $AccountList | Sort-Object -Property dnsroot, account_dnsroot, joinaccount_dnsroot, rootsamaccountname, account_rootsamaccountname, `
            joinaccount_rootsamaccountname, samaccountname, account_samaccountname, joinaccount_samaccountname |
            Out-Gridview -Title "Search Results For: $AccountName"
    }
    else
    {
        return $AccountList
    }


}


function Get-ADMembershipList
{
[CmdletBinding()]
    param (
    [Parameter(ValuefromPipeline=$true,mandatory=$true,Position=0
        ,HelpMessage="Supply an AD User or Group Name. Supports * wildcard.")][String] $AccountName,
    [Parameter(mandatory=$false,Position=1
        ,HelpMessage="all, membersonly, membersofonly [default]")][String] $GroupSearchMethod = "membersofonly",
    [Parameter(mandatory=$false,Position=2)][String] $DomainServer = 
        (Get-ADDomain -Current LocalComputer).DNSRoot,
    [Parameter(mandatory=$false,Position=3
        ,HelpMessage="users, groups, none [default]")][String] $MemberSearchExclude = "none"
    )

    $GroupList = $null
    $Global:ADListTable = @()
    $Global:ADCache = @{}
                 
    #Search for users that match AccountName
    try
    { 
        $UserList = Get-AdUser -Properties objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,memberof,lastlogondate `
        -Filter {SamAccountName -like $AccountName} #-Server $DomainServer        
    }
    catch
    {
        #Workout a list of users that cannot be found
        $UserList=$null
    }
    if($UserList)
    {
        #Add found users and get membership of each
        foreach($User in $UserList)
        {
            # Define User Hash Properties
            $ADListItem = [ordered]@{
            ObjectClass=$User.objectclass
            DNSRoot=$DomainServer
            SamAccountName=$User.SamAccountName
            DisplayName=$User.DisplayName
            Comment=$User.SamAccountName
            Enabled=$User.enabled
            WhenChanged=$User.whenchanged
            WhenCreated=$User.whencreated
            LastLogonDate=$User.lastlogondate
            DN=$User.distinguishedname
            RootSID=$User.sid
            RootSamAccountName=$User.SamAccountName
            SID=$User.sid}
            

            #Add User to List
            $Global:ADListTable += new-object psobject -property $ADListItem

            #Check if search is up the tree
            if($GroupSearchMethod -ne "membersonly")
            {
                #Obtain list of groups the user is a member of
                $UserGroupList = $User | select -ExpandProperty memberof

                foreach($Group in $UserGroupList)
                {
                    #Traverse groups recursively for parent groups
                    Get-ADNestedGroupMembers -SearchAccount $Group -RootSamAccountName $ADListItem.RootSamAccountName -RootSID $ADListItem.RootSID `
                    -Comment $ADListItem.Comment -MemberSearchMethod "membersof" -MemberSearchExclude $MemberSearchExclude #-Server $DomainServer
                }
            }
        }
    }
    #Search for groups that match AccountName
    try
    {
        $GroupList = Get-AdGroup -Properties objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,memberof,members `
        -Filter {SamAccountName -like $AccountName} #-Server $DomainServer
    }
    catch
    {
        #Workout a list of groups that cannot be found
        $GroupList=$null
    }
    if ($GroupList)
    {
        #Add found groups and get members of each
        foreach($UserGroup in $GroupList)
        {
            # Define User Hash Properties
            $ADListItem = [ordered]@{
            ObjectClass=$UserGroup.objectclass
            DNSRoot=$DomainServer
            SamAccountName=$UserGroup.SamAccountName
            DisplayName=$UserGroup.DisplayName
            Comment=$UserGroup.SamAccountName
            Enabled=$UserGroup.enabled
            WhenChanged=$UserGroup.whenchanged
            WhenCreated=$UserGroup.whencreated
            LastLogonDate=if($UserGroup.objectclass -eq "user"){$UserGroup.lastlogondate} else {$null}
            DN=$UserGroup.distinguishedname
            RootSID=$UserGroup.sid
            RootSamAccountName=$UserGroup.SamAccountName
            SID=$UserGroup.sid}
            
            #Add Group to List
            $Global:ADListTable += new-object psobject -property $ADListItem
            if($GroupSearchMethod -ne "membersofonly")
            {
                #Obtain list of groups and users that are a member of the current group
                $UserGroupList = $UserGroup | select -ExpandProperty members
            
                foreach($Group in $UserGroupList)
                {
                    #Traverse down to get members authorized through this group
                    Get-ADNestedGroupMembers -SearchAccount $Group -Server $DomainServer -RootSamAccountName $ADListItem.RootSamAccountName -RootSID $ADListItem.RootSID `
                    -Comment $ADListItem.Comment -MemberSearchMethod "members" -MemberSearchExclude $MemberSearchExclude
                }
            }
            #Check if search is limited to a search down the tree
            if($GroupSearchMethod -ne "membersonly")
            {
                #Obtain list of groups that the current group is a member of
                $UserGroupList = $UserGroup | select -ExpandProperty memberof
                foreach($Group in $UserGroupList)
                {
                    #Traverse up to get all additional groups that could potentially supply rights to this group
                    Get-ADNestedGroupMembers -SearchAccount $Group -Server $DomainServer -RootSamAccountName $ADListItem.RootSamAccountName -RootSID $ADListItem.RootSID `
                    -Comment $ADListItem.Comment -MemberSearchMethod "membersof" -MemberSearchExclude $MemberSearchExclude
                }
            }
        }
    }
    return $Global:ADListTable

}

function Get-ADNestedGroupMembers
{
[CmdletBinding()]
    param (
    [Parameter(ValuefromPipeline=$true,mandatory=$true,Position=0
        ,HelpMessage="Supply an AD Group or User Name.")][String] $SearchAccount,
    [Parameter(ValuefromPipeline=$true,mandatory=$false,Position=1)][String] $Server = 
        (Get-ADDomain -Current LocalComputer).DNSRoot,
    [Parameter(mandatory=$false,Position=2)][String] $RootSamAccountName,
    [Parameter(mandatory=$false,Position=3)][String] $RootSID,
    [Parameter(mandatory=$false,Position=4)][String] $Comment,
    [Parameter(mandatory=$false,Position=5
    ,HelpMessage="members, membersof [default]")][String] $MemberSearchMethod="membersof",
    [Parameter(mandatory=$false,Position=6
    ,HelpMessage="users, groups, none [default]")][String] $MemberSearchExclude = "none"
    )

    # only worries about getting groups up the tree
    if($MemberSearchMethod -eq "membersof")
    {
        if ($Global:ADCache.ContainsKey($SearchAccount))
        {   
            $MainGroup = $Global:ADCache[$SearchAccount].Psobject.Copy()
        }
        else
        {
            try
            {
                $MainGroup = Get-AdGroup -Identity $SearchAccount -Properties objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,memberof #-Server $Server
                $Global:ADCache.Add($MainGroup.DistinguishedName, $MainGroup)
            }
            catch
            {
                #Workout error list of groups that cannot be found
                $MainGroup = $null
            }
        }

            if($MainGroup)
            {
                # Define Group Hash Properties
                $ADListItem = [ordered]@{
                ObjectClass=$MainGroup.objectclass
                DNSRoot=$Server
                SamAccountName=$MainGroup.SamAccountName
                DisplayName=$MainGroup.DisplayName
                Comment=($Comment, $MainGroup.SamAccountName -join "->")
                Enabled=$MainGroup.enabled
                WhenChanged=$MainGroup.whenchanged
                WhenCreated=$MainGroup.whencreated
                LastLogonDate=if($MainGroup.objectclass -eq "user"){$MainGroup.lastlogondate} else {$null}
                DN=$MainGroup.distinguishedname
                RootSID=$RootSID
                RootSamAccountName=$RootSamAccountName
                SID=$MainGroup.sid}

                #Add Group to List
                $Global:ADListTable += new-object psobject -property $ADListItem
                
                #Obtain list of groups that the current group is a member of
                $UserGroupList = $MainGroup | select -ExpandProperty memberof
                foreach($Group in $UserGroupList)
                {
                    #Traverse up to get all additional groups that could potentially supply rights to this group
                    Get-ADNestedGroupMembers -SearchAccount $Group -Server $ADListItem.DNSRoot -RootSamAccountName $RootSamAccountName `
                        -RootSID $RootSID -Comment $ADListItem.Comment -MemberSearchMethod "membersof" -MemberSearchExclude $MemberSearchExclude
                }

             }

        
    }

    # worries about getting groups and users children down the tree
    if($MemberSearchMethod -eq "members")
    {
        if($MemberSearchExclude -ne "users")
        {
            if ($Global:ADCache.ContainsKey($SearchAccount))
            {   
                $U = $Global:ADCache[$SearchAccount].Psobject.Copy()
            }
            else
            {
                try
                {
                    #check if user or group
                    $U = Get-ADUser -Identity $SearchAccount -Properties objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,lastlogondate
                    $Global:ADCache.Add($U.DistinguishedName, $U)
                }
                catch
                {
                    #Workout list of users that cannot be found
                    $U=$null
                }
            }
            if($U)
            {

                # Define Group Hash Properties
                $ADListItem = [ordered]@{
                ObjectClass=$U.objectclass
                DNSRoot=$Server
                SamAccountName=$U.SamAccountName
                DisplayName=$U.DisplayName
                Comment=($Comment, $U.SamAccountName -join "<-")
                Enabled=$U.enabled
                WhenChanged=$U.whenchanged
                WhenCreated=$U.whencreated
                LastLogonDate=if($U.objectclass -eq "user"){$U.lastlogondate} else {$null}
                DN=$U.distinguishedname
                RootSID=$RootSID
                RootSamAccountName=$RootSamAccountName
                SID=$U.sid}
                


                $Global:ADListTable += new-object psobject -property $ADListItem
                return
            }
        }

        if ($Global:ADCache.ContainsKey($SearchAccount))
        {   
            $Gl = $Global:ADCache[$SearchAccount].Psobject.Copy()
        }
        else
        {
            try
            {
                $Gl = Get-ADGroup -Identity $SearchAccount -Properties objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,members
                $Global:ADCache.Add($Gl.DistinguishedName, $Gl)
            }
            catch
            {
                #Workout list of groups that cannot be found
                $Gl=$null
            }
        }
        foreach($G in $Gl)
        {
            # Define Group Hash Properties
            $ADListItem = [ordered]@{
            ObjectClass=$G.objectclass
            DNSRoot=$Server
            SamAccountName=$G.SamAccountName
            DisplayName=$G.DisplayName
            Comment=($Comment, $G.SamAccountName -join "<-")
            Enabled=$G.enabled
            WhenChanged=$G.whenchanged
            WhenCreated=$G.whencreated
            LastLogonDate=if($G.objectclass -eq "user"){$G.lastlogondate} else {$null}
            DN=$G.distinguishedname
            RootSID=$RootSID
            RootSamAccountName=$RootSamAccountName
            SID=$G.sid}
                    
            if($MemberSearchExclude -ne "groups")
            {
                $Global:ADListTable += new-object psobject -property $ADListItem
            }

            $UserGroupList = $G | select -ExpandProperty members
                foreach($Group in $UserGroupList)
                {
                    Get-ADNestedGroupMembers -SearchAccount $Group -Server $ADListItem.DNSRoot -RootSamAccountName $RootSamAccountName -RootSID $RootSID `
                    -Comment $ADListItem.Comment -MemberSearchMethod "members" -MemberSearchExclude $MemberSearchExclude
                }
        }
    }
}

function Get-UserGroupQuick {
#Modified version of script by Vadims Podans
#https://www.sysadmins.lv/blog-en/efficient-way-to-get-ad-user-membership-recursively-with-powershell.aspx
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [String[]]$UserName
    )
    begin {
        # introduce two lookup hashtables. First will contain cached AD groups,
        # second will contain user groups. We will reuse it for each user.
        # format: Key = group distinguished name, Value = ADGroup object
        $ADGroupCache = @{}
        $UserGroups = @{}
        $OutObject = @()
        # define recursive function to recursively process groups.
        function __findPath ([string]$currentGroup, [string]$comment) {
            Write-Verbose "Processing group: $currentGroup"
            # we must do processing only if the group is not already processed.
            # otherwise we will get an infinity loop
            if (!$UserGroups.ContainsKey($currentGroup)) {
                # retrieve group object, either, from cache (if is already cached)
                # or from Active Directory
                $groupObject = if ($ADGroupCache.ContainsKey($currentGroup)) {
                    Write-Verbose "Found group in cache: $currentGroup"
                    $ADGroupCache[$currentGroup].Psobject.Copy()
                } else {
                    Write-Verbose "Group: $currentGroup is not presented in cache. Retrieve and cache."
                    
                    $g = Get-ADGroup -Identity $currentGroup -Property objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,memberof
                    # immediately add group to local cache:
                    
                    $ADGroupCache.Add($g.DistinguishedName, $g)
                    $g
                }
                
                $c = $comment + "->" + $groupObject.SamAccountName
                
                $UserGroups.Add($c, $groupObject)
                                
                Write-Verbose "Membership Path:  $c"
                foreach ($p in $groupObject.MemberOf) {
                       __findPath $p $c
                }
            } else {Write-Verbose "Closed walk or duplicate on '$currentGroup'. Skipping."}
        }
    }
    process {
    $stime=(Get-Date)
        foreach ($user in $UserName) {
            Write-Verbose "========== $user =========="
            # clear group membership prior to each user processing
            $UserObject = Get-ADUser -Identity $user -Property objectclass,sid,whenchanged,whencreated,samaccountname,displayname,enabled,distinguishedname,memberof
            $UserObject.MemberOf | ForEach-Object {__findPath $_ $UserObject.SamAccountName}
}
            foreach($g in $UserGroups.GetEnumerator())
            {
                $OutObject += [pscustomobject]@{
                    ObjectClass = $g.value.ObjectClass;
                    RootSamAccountName = $UserObject.SamAccountName;
                    MemberOf = $g.value.SamAccountName;
                    DisplayName = $g.value.DisplayName;
                    Comment = $g.key;
                    Enabled = $g.value.enabled;
                    WhenChanged = $g.value.WhenChanged;
                    WhenCreated = $g.value.WhenCreated;
                    SID = $g.value.sid;
                }
            }
            $etime=(Get-Date)
            Write-Verbose "$($etime-$stime) Speedy Search Completed"
            return $OutObject
        }
    }
