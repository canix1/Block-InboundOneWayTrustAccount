# Block-InboundOneWayTrustAccount

.DESCRIPTION
    A tool that prevent an admin in a trusted domain to access your domain using the TDO user credentials

.EXAMPLE
    .\Block-InboundOneWayTrustAccount.ps1 -protect

   Protect the incoming trusts outside of your forest by preventing the TDO user account from perform authentication.

.EXAMPLE
    .\Block-InboundOneWayTrustAccount.ps1 -unprotect

    Reverse any previously added protection
