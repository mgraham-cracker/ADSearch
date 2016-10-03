# ADSearch
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
