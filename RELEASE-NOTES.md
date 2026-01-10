###################################################################################
                            --- SECRET//NOFORN ---
###################################################################################

                            *****RELEASE NOTES*****

Version 1.2
*New Features
    - Now supports remote fibers! (arg: /r)
        - Suspends target thread, modifies RIP, sets RDI, resumes
        - fiber_stub:
            - Converts hijacked thread -> fiber
            - Creates new fiber pointing to shellcode
            - Switches execution to shellcode fiber

Version 1.1
*New Features
    - Added elementary AV/EDR evasion
        - Patches AMSI
        - Patches ETW
        - Unhooks ntdll

###################################################################################
                            --- SECRET//NOFORN ---
###################################################################################