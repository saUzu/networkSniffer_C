#ifndef BIRAK_H__
#define BIRAK_H__
#define BIRAK(isaretci)  \
    if (isaretci)        \
    {                    \
        free(isaretci);  \
        isaretci = NULL; \
    }
#endif