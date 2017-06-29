###############################################################################
#    Title:        DC Replication Fix
#    Revision:     1.5 (PUBLIC)
#    Author:       DrPrEsq ; https://github.com/potr/ADFix
#    Date:         28 June 2017
#
#    Purpose:      To restore replication between DC and FSMO Master when replication is failing
#                  
#    
#    Dependancies: 1) Access to the desktop of the affected DC via a Domain Administrator Account
#                  2) A Copy of this script on the desktop of the affected DC
#                  3) Connectivity between the affected DSC and the FSMO Master
#    
#    How to Run:   Right Click on the script and choose 'Run With PowerShell'
#
#    Rev history:  CURRENT     - Removed all organization specific information and replaced it with dynamically constructed #     #                                versions for public release
#                  1.4         - Broke out more code from FixAD into functions and made FixAD more efficient overall
#                  1.3         - Added write-progress, text coloring, and refined menus and outputs
#                  1.2         - refined control logic in replication portion to reduce code length; 
#                                improved error handling for all sections
#                  1.1(BETA)   - added rudementary error handling throughout, 
#                                verbose commenting of all functions implemented, 
#                                added menues/headers, and rev history info
#                  1.0(ALPHA)  - Script functioning in linear procedural fashion; limited error handling
#
#     Disclaimer:  This script is provided for free without warranty or support; no rights reserved; please give author credit.
#
################################################################################
